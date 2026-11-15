/*
 * deploy_test.c — orchestration tests for `stackctl deploy`.
 *
 * Exercises the provenance -> freshness -> AMI preflight -> publish -> CFN
 * change-set pipeline, rollback of an existing tag, idempotency, confirmation
 * and failure mapping. All external stages are injected; no git/bazel/AWS.
 */

#include "deploy_internal.h"

#include "aws_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "yyjson.h"

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

enum trace_tag {
    TRACE_PROVENANCE = 1,
    TRACE_TEMPLATE,
    TRACE_FRESHNESS,
    TRACE_BUCKET,
    TRACE_AMI_RESOLVE,
    TRACE_AMI_EXISTS,
    TRACE_RELEASE_EXISTS,
    TRACE_VERIFY,
    TRACE_PUBLISH,
    TRACE_AWS_INIT,
    TRACE_CFN_CREATE,
    TRACE_DESCRIBE,
    TRACE_CREATE_CS,
    TRACE_WAIT_CS,
    TRACE_DESC_CS,
    TRACE_EXECUTE,
    TRACE_WAIT_STACK,
    TRACE_DELETE_CS,
    TRACE_DELETE_STACK,
    TRACE_LIVE,
    TRACE_PRUNE
};

typedef struct fake {
    int trace[96];
    int trace_count;

    int provenance_rc;
    char provenance_tag[64];
    int freshness_rc;
    int bucket_rc;
    int ami_resolve_rc;
    char ami_value[64];
    int ami_found;
    int rel_exists;
    int rel_exists_rc;
    int verify_rc;
    char verify_sha[65];
    int publish_rc;
    char publish_sha[65];
    int live_count;
    int live_rc;
    int prune_rc;
    int prune_calls;
    char prune_pinned[128];
    char prune_previous[128];
    char prune_uploaded[128];

    int stack_present;
    cfn_stack_status status;
    int describe_rc;
    int create_rc;
    int wait_cs_rc;
    int describe_cs_rc;
    int change_count;
    int execute_rc;
    int wait_stack_rc;
    int delete_cs_rc;
    int delete_stack_rc;

    int published_count;
    int verified_count;
    int executed;
    int deleted_change_sets;
    int deleted_stacks;

    int read_templates;
    int last_type;
    unsigned last_caps;
    char last_stack[128];
    char last_template[512];
    size_t last_param_count;
    char params[16][128];
    char param_values[16][256];
    size_t last_tag_count;
    char tag_keys[8][128];
    char tag_values[8][256];

    size_t old_param_count;
    char old_param_keys[8][64];
    char old_param_values[8][128];

    int confirm_calls;
    int confirm_result;
} fake;

static void trace(fake *f, int tag) {
    if (f->trace_count < (int)(sizeof(f->trace) / sizeof(f->trace[0]))) {
        f->trace[f->trace_count++] = tag;
    }
}

static int trace_index(const fake *f, int tag) {
    for (int i = 0; i < f->trace_count; i++) {
        if (f->trace[i] == tag) {
            return i;
        }
    }
    return -1;
}

static const char *tag_value(const fake *f, const char *key) {
    for (size_t i = 0; i < f->last_tag_count; i++) {
        if (strcmp(f->tag_keys[i], key) == 0) {
            return f->tag_values[i];
        }
    }
    return NULL;
}

static void check_release_tags(const fake *f, const char *tag,
                               const char *sha) {
    const char *tagged = tag_value(f, "stackctl:release-tag");
    const char *sha_tagged = tag_value(f, "stackctl:release-sha");

    CHECK(tagged != NULL && strcmp(tagged, tag) == 0,
          "stack tagged with stackctl:release-tag");
    CHECK(sha_tagged != NULL && strcmp(sha_tagged, sha) == 0,
          "stack tagged with stackctl:release-sha");
}

/* ------------------------------------------------------------------------- */
/* Fakes                                                                     */
/* ------------------------------------------------------------------------- */

static int fake_provenance(void *ud, const char *repo_root, int allow_dirty,
                           char *tag, size_t cap) {
    fake *f = ud;

    (void)repo_root;
    (void)allow_dirty;
    trace(f, TRACE_PROVENANCE);
    if (f->provenance_rc != 0) {
        return f->provenance_rc;
    }
    snprintf(tag, cap, "%s", f->provenance_tag);
    return 0;
}

static int fake_freshness(void *ud, const char *repo_root, const char *targets) {
    fake *f = ud;

    (void)repo_root;
    (void)targets;
    trace(f, TRACE_FRESHNESS);
    return f->freshness_rc;
}

static int fake_bucket(void *ud, const char *project, const char *region,
                       char *out, size_t cap) {
    fake *f = ud;

    (void)project;
    (void)region;
    trace(f, TRACE_BUCKET);
    snprintf(out, cap, "demo-artifacts-123456789012-us-east-1");
    return f->bucket_rc;
}

static int fake_resolve_ami(void *ud, const stackctl_config *cfg,
                            const char *region, const char *arch, char *out,
                            size_t cap) {
    fake *f = ud;

    (void)cfg;
    (void)region;
    (void)arch;
    trace(f, TRACE_AMI_RESOLVE);
    if (f->ami_resolve_rc != 0) {
        return f->ami_resolve_rc;
    }
    snprintf(out, cap, "%s", f->ami_value[0] != '\0' ? f->ami_value : "ami-ok");
    return 0;
}

static int fake_ami_exists(void *ud, const char *region, const char *ami,
                           int *found) {
    fake *f = ud;

    (void)region;
    (void)ami;
    trace(f, TRACE_AMI_EXISTS);
    *found = f->ami_found;
    return 0;
}

static int fake_release_exists(void *ud, const char *bucket, const char *tag,
                               int *exists) {
    fake *f = ud;

    (void)bucket;
    (void)tag;
    trace(f, TRACE_RELEASE_EXISTS);
    if (f->rel_exists_rc != 0) {
        return f->rel_exists_rc;
    }
    *exists = f->rel_exists;
    return 0;
}

static int fake_verify(void *ud, const char *bucket, const char *tag,
                       char *sha_out, size_t cap) {
    fake *f = ud;

    (void)bucket;
    (void)tag;
    trace(f, TRACE_VERIFY);
    f->verified_count++;
    if (f->verify_rc != 0) {
        return f->verify_rc;
    }
    snprintf(sha_out, cap, "%s", f->verify_sha);
    return 0;
}

static int fake_publish(void *ud, const char *bucket, const char *tag,
                        const char *repo_root, const char *targets,
                        char *sha_out, size_t cap) {
    fake *f = ud;

    (void)bucket;
    (void)tag;
    (void)repo_root;
    (void)targets;
    trace(f, TRACE_PUBLISH);
    f->published_count++;
    if (f->publish_rc != 0) {
        return f->publish_rc;
    }
    snprintf(sha_out, cap, "%s", f->publish_sha);
    return 0;
}

static int fake_count_live(void *ud, const char *region, int *count) {
    fake *f = ud;

    (void)region;
    trace(f, TRACE_LIVE);
    *count = f->live_count;
    return f->live_rc;
}

static int fake_prune(void *ud, const char *bucket, const char *pinned,
                      const char *previous, const char *just_uploaded) {
    fake *f = ud;

    (void)bucket;
    trace(f, TRACE_PRUNE);
    f->prune_calls++;
    snprintf(f->prune_pinned, sizeof(f->prune_pinned), "%s",
             pinned != NULL ? pinned : "");
    snprintf(f->prune_previous, sizeof(f->prune_previous), "%s",
             previous != NULL ? previous : "");
    snprintf(f->prune_uploaded, sizeof(f->prune_uploaded), "%s",
             just_uploaded != NULL ? just_uploaded : "");
    return f->prune_rc;
}

static int fake_read_template_path(void *ud, const char *path,
                                   char **body_out) {
    fake *f = ud;
    FILE *file;
    long size;
    char *body;

    trace(f, TRACE_TEMPLATE);
    file = fopen(path, "rb");
    if (file == NULL) {
        return errno != 0 ? errno : ENOENT;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return EIO;
    }
    size = ftell(file);
    if (size < 0) {
        fclose(file);
        return EIO;
    }
    rewind(file);
    body = malloc((size_t)size + 1);
    if (body == NULL) {
        fclose(file);
        return ENOMEM;
    }
    if (fread(body, 1, (size_t)size, file) != (size_t)size) {
        free(body);
        fclose(file);
        return EIO;
    }
    fclose(file);
    body[size] = '\0';
    *body_out = body;
    return 0;
}

static int fake_aws_init(void *ud, const char *profile, aws_ctx **out) {
    fake *f = ud;

    (void)profile;
    trace(f, TRACE_AWS_INIT);
    *out = (aws_ctx *)f;
    return 0;
}

static void fake_aws_free(void *ud, aws_ctx *aws) {
    (void)ud;
    (void)aws;
}

static int fake_cfn_create(void *ud, aws_ctx *aws, cfn_client **out) {
    fake *f = ud;

    (void)aws;
    trace(f, TRACE_CFN_CREATE);
    *out = (cfn_client *)f;
    return 0;
}

static void fake_cfn_destroy(void *ud, cfn_client *client) {
    (void)ud;
    (void)client;
}

static int fake_describe(void *ud, cfn_client *client, const char *region,
                         const char *stack_name, cfn_stack_list *out) {
    fake *f = ud;

    (void)client;
    (void)region;
    trace(f, TRACE_DESCRIBE);
    if (f->describe_rc != 0) {
        return f->describe_rc;
    }
    if (!f->stack_present) {
        return ENOENT;
    }
    out->items = calloc(1, sizeof(*out->items));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    snprintf(out->items[0].stack_name, sizeof(out->items[0].stack_name), "%s",
             stack_name);
    out->items[0].status = f->status;
    if (f->old_param_count > 0) {
        size_t n = f->old_param_count;

        out->items[0].parameters = calloc(n, sizeof(*out->items[0].parameters));
        if (out->items[0].parameters == NULL) {
            free(out->items);
            out->items = NULL;
            out->count = 0;
            return ENOMEM;
        }
        out->items[0].parameter_count = n;
        for (size_t i = 0; i < n; i++) {
            snprintf(out->items[0].parameters[i].key,
                     sizeof(out->items[0].parameters[i].key), "%s",
                     f->old_param_keys[i]);
            snprintf(out->items[0].parameters[i].value,
                     sizeof(out->items[0].parameters[i].value), "%s",
                     f->old_param_values[i]);
        }
    }
    return 0;
}

static void fake_stack_list_free(void *ud, cfn_stack_list *list) {
    (void)ud;
    if (list != NULL) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->items[i].parameters);
        }
        free(list->items);
        list->items = NULL;
        list->count = 0;
    }
}

static int fake_create_cs(void *ud, cfn_client *client, const char *region,
                          const cfn_change_set_spec *spec,
                          cfn_change_set_result *out) {
    fake *f = ud;

    (void)client;
    (void)region;
    trace(f, TRACE_CREATE_CS);
    f->last_type = (int)spec->type;
    f->last_caps = spec->capabilities;
    snprintf(f->last_stack, sizeof(f->last_stack), "%s", spec->stack_name);
    snprintf(f->last_template, sizeof(f->last_template), "%.*s", 511,
             spec->template_body != NULL ? spec->template_body : "");
    f->last_param_count = spec->parameter_count;
    for (size_t i = 0; i < spec->parameter_count && i < 16; i++) {
        snprintf(f->params[i], sizeof(f->params[i]), "%s",
                 spec->parameters[i].key);
        snprintf(f->param_values[i], sizeof(f->param_values[i]), "%s",
                 spec->parameters[i].value);
    }
    f->last_tag_count = spec->tag_count;
    for (size_t i = 0; i < spec->tag_count && i < 8; i++) {
        snprintf(f->tag_keys[i], sizeof(f->tag_keys[i]), "%s",
                 spec->tags[i].key);
        snprintf(f->tag_values[i], sizeof(f->tag_values[i]), "%s",
                 spec->tags[i].value);
    }
    snprintf(out->change_set_id, sizeof(out->change_set_id), "cs-1");
    return f->create_rc;
}

static int fake_wait_cs(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs, int attempts,
                        int interval, int *timed_out) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    (void)attempts;
    (void)interval;
    trace(f, TRACE_WAIT_CS);
    if (timed_out != NULL)
        *timed_out = 0;
    return f->wait_cs_rc;
}

static int fake_desc_cs(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs,
                        cfn_change_set *out) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    trace(f, TRACE_DESC_CS);
    out->change_count = (size_t)f->change_count;
    out->execution_status = CFN_CHANGE_SET_EXECUTION_AVAILABLE;
    return f->describe_cs_rc;
}

static void fake_change_set_free(void *ud, cfn_change_set *cs) {
    (void)ud;
    (void)cs;
}

static int fake_execute(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    trace(f, TRACE_EXECUTE);
    f->executed++;
    return f->execute_rc;
}

static int fake_delete_cs(void *ud, cfn_client *client, const char *region,
                          const char *stack, const char *cs) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    trace(f, TRACE_DELETE_CS);
    f->deleted_change_sets++;
    return f->delete_cs_rc;
}

static int fake_wait_stack(void *ud, cfn_client *client, const char *region,
                           const char *stack, cfn_wait_operation op,
                           int attempts, int interval, int *timed_out) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)op;
    (void)attempts;
    (void)interval;
    trace(f, TRACE_WAIT_STACK);
    if (timed_out != NULL)
        *timed_out = 0;
    return f->wait_stack_rc;
}

static int fake_delete_stack(void *ud, cfn_client *client, const char *region,
                             const char *stack) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    trace(f, TRACE_DELETE_STACK);
    f->deleted_stacks++;
    return f->delete_stack_rc;
}

static deploy_ops fake_ops = {
    .git_provenance = fake_provenance,
    .freshness = fake_freshness,
    .resolve_bucket = fake_bucket,
    .resolve_ami = fake_resolve_ami,
    .ami_exists = fake_ami_exists,
    .release_exists = fake_release_exists,
    .verify_release = fake_verify,
    .publish_release = fake_publish,
    .count_live_instances = fake_count_live,
    .prune_releases = fake_prune,
    .aws_init = fake_aws_init,
    .aws_free = fake_aws_free,
    .cfn_create = fake_cfn_create,
    .cfn_destroy = fake_cfn_destroy,
    .describe_stacks = fake_describe,
    .stack_list_free = fake_stack_list_free,
    .create_change_set = fake_create_cs,
    .wait_change_set = fake_wait_cs,
    .describe_change_set = fake_desc_cs,
    .change_set_free = fake_change_set_free,
    .execute_change_set = fake_execute,
    .delete_change_set = fake_delete_cs,
    .wait_stack = fake_wait_stack,
    .delete_stack = fake_delete_stack,
};

/* Variant that exercises template loading; the base fake keeps the seam NULL
 * so the existing pipeline tests do not need a filesystem template. */
static deploy_ops configured_ops;

/* ------------------------------------------------------------------------- */
/* Fixture                                                                   */
/* ------------------------------------------------------------------------- */

static const char *base_env =
    "PROJECT=demo\n"
    "REGION=us-east-1\n"
    "ARCH=amd64\n"
    "SPOT_DEFAULT=false\n"
    "AMI_POLICY=pinned\n"
    "AMI_ID_AMD64=ami-0123456789abcdef0\n"
    "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"
    "ROOT_VOLUME_SIZE=100\n"
    "KEY_NAME=demo-key\n"
    "SSH_IDENTITY=/home/operator/.ssh/demo\n"
    "BUCKET_MODULES=artifact,cert\n"
    "ENABLE_IMAGE_BUILDER=false\n"
    "SETUP_ENTRYPOINT=deploy.sh\n"
    "SSH_PORT=22\n"
    "OPERATOR_CIDR=203.0.113.0/24\n"
    "INGRESS_TCP=443\n"
    "INGRESS_UDP=\n"
    "RELEASE_TARGETS=//app:deploy.tar.gz\n"
    "RELEASE_PREFIXES=releases/\n";

typedef struct fixture {
    char root[PATH_MAX];
    char config_dir[PATH_MAX];
} fixture;

static void mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t len;

    snprintf(buffer, sizeof(buffer), "%s", path);
    len = strlen(buffer);
    for (size_t i = 1; i < len; i++) {
        if (buffer[i] == '/') {
            buffer[i] = '\0';
            (void)mkdir(buffer, 0755);
            buffer[i] = '/';
        }
    }
    (void)mkdir(buffer, 0755);
}

static void write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    fputs(text, file);
    fclose(file);
}

static void append_text(const char *path, const char *text) {
    FILE *file = fopen(path, "a");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    fputs(text, file);
    fclose(file);
}

static char *read_text_file(const char *path) {
    FILE *file = fopen(path, "rb");
    long size;
    char *body;

    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    size = ftell(file);
    if (size < 0) {
        fclose(file);
        return NULL;
    }
    rewind(file);
    body = malloc((size_t)size + 1);
    if (body == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(body, 1, (size_t)size, file) != (size_t)size) {
        free(body);
        fclose(file);
        return NULL;
    }
    fclose(file);
    body[size] = '\0';
    return body;
}

static char *read_runfile(const char *relative) {
    const char *srcdir = getenv("TEST_SRCDIR");
    const char *workspace = getenv("TEST_WORKSPACE");
    char path[PATH_MAX];

    if (srcdir == NULL || workspace == NULL) {
        return NULL;
    }
    snprintf(path, sizeof(path), "%s/%s/%s", srcdir, workspace, relative);
    return read_text_file(path);
}

static void fixture_install_canonical(fixture *fx) {
    char path[PATH_MAX];
    char *text = read_runfile("deploy/stackctl-infra.yaml");

    if (text == NULL) {
        fprintf(stderr, "cannot load the canonical infra template\n");
        exit(1);
    }
    snprintf(path, sizeof(path), "%s/deploy/stackctl-infra.yaml", fx->root);
    write_text(path, text);
    free(text);
}

static void fixture_install_override(fixture *fx, const char *relative,
                                     const char *runfile_relative,
                                     const char *prefix) {
    char path[PATH_MAX];
    char *text = read_runfile(runfile_relative);
    char *body;

    if (text == NULL) {
        fprintf(stderr, "cannot load fixture %s\n", runfile_relative);
        exit(1);
    }
    snprintf(path, sizeof(path), "%s/%s", fx->root, relative);
    body = malloc((prefix != NULL ? strlen(prefix) : 0) + strlen(text) + 1);
    if (body == NULL) {
        exit(1);
    }
    body[0] = '\0';
    if (prefix != NULL) {
        strcpy(body, prefix);
    }
    strcat(body, text);
    write_text(path, body);
    free(body);
    free(text);
}

static void fixture_append_env(fixture *fx, const char *line) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/.env", fx->config_dir);
    append_text(path, line);
}

static void fixture_write_env(fixture *fx, const char *text) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/.env", fx->config_dir);
    write_text(path, text);
}

static void fixture_init(fixture *fx) {
    char template[] = "/tmp/stackctl-deploy-XXXXXX";
    char *root = mkdtemp(template);
    char path[PATH_MAX];

    memset(fx, 0, sizeof(*fx));
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof(fx->root), "%s", root);
    snprintf(fx->config_dir, sizeof(fx->config_dir), "%s/deploy/aws", fx->root);
    mkdir_p(fx->config_dir);
    snprintf(path, sizeof(path), "%s/MODULE.bazel", fx->root);
    write_text(path, "");
    snprintf(path, sizeof(path), "%s/.env", fx->config_dir);
    write_text(path, base_env);
}

static stackctl_config *load_config(const fixture *fx) {
    stackctl_config *cfg = NULL;

    if (config_load(fx->config_dir, 0, NULL, &cfg) != 0) {
        return NULL;
    }
    return cfg;
}

static int confirm_yes(void *ud, const char *prompt) {
    fake *f = ud;

    (void)prompt;
    f->confirm_calls++;
    return f->confirm_result;
}

static deploy_env make_env(fake *f, stackctl_config *cfg, fixture *fx) {
    deploy_env env = {0};

    env.cfg = cfg;
    env.config_dir = fx->config_dir;
    env.out = stdout;
    env.err = stderr;
    if (f->read_templates != 0) {
        configured_ops = fake_ops;
        configured_ops.read_template_path = fake_read_template_path;
        env.ops = &configured_ops;
    } else {
        env.ops = &fake_ops;
    }
    env.ops_ud = f;
    env.confirm = confirm_yes;
    env.confirm_ud = f;

    f->ami_found = 1;
    f->change_count = 1;
    f->confirm_result = CLI_CONFIRM_YES;
    snprintf(f->provenance_tag, sizeof(f->provenance_tag), "v1.2.3");
    snprintf(f->verify_sha, sizeof(f->verify_sha),
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(f->publish_sha, sizeof(f->publish_sha),
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    return env;
}

/* ------------------------------------------------------------------------- */
/* Cases                                                                     */
/* ------------------------------------------------------------------------- */

static int stream_contains(FILE *stream, const char *needle) {
    char buffer[8192];
    size_t got;

    if (stream == NULL) {
        return 0;
    }
    fflush(stream);
    rewind(stream);
    got = fread(buffer, 1, sizeof buffer - 1, stream);
    buffer[got] = '\0';
    clearerr(stream);
    return strstr(buffer, needle) != NULL;
}

static void test_null_env(void) {
    CHECK(deploy_run(NULL) == CLI_EXIT_USAGE, "NULL env is usage");
}

static void test_provenance_failure(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.provenance_rc = CLI_EXIT_VERIFY;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_VERIFY, "provenance failure exits 3");
    CHECK(trace_index(&f, TRACE_FRESHNESS) < 0, "freshness not reached");
    CHECK(f.published_count == 0, "nothing published");
    config_free(cfg);
}

static void test_ambiguous_tag_is_usage(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.provenance_rc = CLI_EXIT_USAGE;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_USAGE, "ambiguous tag exits 1");
    config_free(cfg);
}

static void test_freshness_failure_is_6(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.freshness_rc = CLI_EXIT_FRESHNESS;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_FRESHNESS, "stale artifacts exit 6");
    CHECK(f.published_count == 0, "stale artifacts are not published");
    config_free(cfg);
}

static void test_skip_build_bypasses_freshness(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.freshness_rc = CLI_EXIT_FRESHNESS;
    env = make_env(&f, cfg, &fx);
    env.skip_build = 1;
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "skip-build proceeds");
    CHECK(trace_index(&f, TRACE_FRESHNESS) < 0, "freshness skipped");
    CHECK(f.published_count == 1, "still publishes");
    config_free(cfg);
}

static void test_ami_preflight_failure_is_usage(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.ami_found = 0;
    env = make_env(&f, cfg, &fx);
    f.ami_found = 0;
    CHECK(deploy_run(&env) == CLI_EXIT_USAGE, "missing AMI exits 1");
    CHECK(f.published_count == 0, "no publish after AMI preflight failure");
    CHECK(trace_index(&f, TRACE_DESCRIBE) < 0, "no stack mutation");
    config_free(cfg);
}

static void test_in_progress_stack_is_aws(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_IN_PROGRESS;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_AWS, "in-progress stack exits 2");
    CHECK(f.executed == 0, "nothing executed");
    config_free(cfg);
}

static void test_stack_state_recovery_guidance(void) {
    struct {
        cfn_stack_status status;
        const char *needle;
        const char *label;
    } cases[] = {
        {CFN_STACK_STATUS_ROLLBACK_COMPLETE, "delete the stack",
         "ROLLBACK_COMPLETE names the delete-stack recovery"},
        {CFN_STACK_STATUS_UPDATE_ROLLBACK_FAILED, "continue-update-rollback",
         "UPDATE_ROLLBACK_FAILED names continue-update-rollback"},
        {CFN_STACK_STATUS_DELETE_FAILED, "DELETE_FAILED",
         "DELETE_FAILED names the failed stack state"},
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        fixture fx;
        fake f = {0};
        stackctl_config *cfg;
        deploy_env env;
        FILE *err;

        fixture_init(&fx);
        cfg = load_config(&fx);
        f.stack_present = 1;
        f.status = cases[i].status;
        env = make_env(&f, cfg, &fx);
        err = tmpfile();
        env.err = err;
        CHECK(deploy_run(&env) == CLI_EXIT_AWS, cases[i].label);
        CHECK(stream_contains(err, cases[i].needle), cases[i].label);
        CHECK(f.executed == 0, "no change-set execution on a bad stack state");
        if (err != NULL) {
            fclose(err);
        }
        config_free(cfg);
    }
}

static void test_new_release_publishes_then_updates_in_order(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;
    int ami_param = 0;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 4;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "new release deploy succeeds");
    CHECK(strcmp(env.tag, "v1.2.3") == 0, "HEAD tag resolved");
    CHECK(f.published_count == 1, "published once");
    CHECK(f.executed == 1, "stack update executed");
    CHECK(trace_index(&f, TRACE_PROVENANCE) < trace_index(&f, TRACE_FRESHNESS),
          "provenance before freshness");
    CHECK(trace_index(&f, TRACE_FRESHNESS) < trace_index(&f, TRACE_AMI_RESOLVE),
          "freshness before AMI preflight");
    CHECK(trace_index(&f, TRACE_AMI_EXISTS) < trace_index(&f, TRACE_PUBLISH),
          "AMI preflight before publish");
    CHECK(trace_index(&f, TRACE_RELEASE_EXISTS) < trace_index(&f, TRACE_PUBLISH),
          "immutability check before publish");
    CHECK(trace_index(&f, TRACE_PUBLISH) < trace_index(&f, TRACE_CREATE_CS),
          "publish before stack change set");
    CHECK(f.last_type == CFN_CHANGE_SET_TYPE_CREATE, "CREATE change set");
    for (size_t i = 0; i < f.last_param_count; i++) {
        if (strcmp(f.params[i], "AmiIdAmd64") == 0) {
            ami_param = 1;
        }
        if (strcmp(f.params[i], "ReleaseTag") == 0) {
            CHECK(strcmp(f.param_values[i], "v1.2.3") == 0,
                  "ReleaseTag parameter");
        }
        if (strcmp(f.params[i], "ReleaseManifestSha256") == 0) {
            CHECK(strcmp(f.param_values[i], f.publish_sha) == 0,
                  "manifest sha parameter");
        }
    }
    CHECK(ami_param, "pinned AmiId parameter present");
    check_release_tags(&f, "v1.2.3", f.publish_sha);
    config_free(cfg);
}

static void test_update_tags_release_identity(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.rel_exists = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "existing release update succeeds");
    CHECK(f.last_type == CFN_CHANGE_SET_TYPE_UPDATE, "UPDATE change set");
    check_release_tags(&f, "v1.2.3", f.verify_sha);
    config_free(cfg);
}

static void test_rollback_existing_tag_skips_gates_and_publish(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.rel_exists = 1;
    env = make_env(&f, cfg, &fx);
    env.tag_arg = "v1.0.0";
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "rollback succeeds");
    CHECK(trace_index(&f, TRACE_PROVENANCE) < 0, "rollback skips provenance");
    CHECK(trace_index(&f, TRACE_FRESHNESS) < 0, "rollback skips freshness");
    CHECK(f.published_count == 0, "rollback never publishes");
    CHECK(f.verified_count == 1, "rollback verifies the manifest");
    CHECK(strcmp(env.tag, "v1.0.0") == 0, "rollback tag retained");
    CHECK(f.executed == 1, "stack update executed");
    check_release_tags(&f, "v1.0.0", f.verify_sha);
    config_free(cfg);
}

static void test_rollback_missing_tag_is_verify(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.rel_exists = 0;
    env = make_env(&f, cfg, &fx);
    env.tag_arg = "v1.0.0";
    CHECK(deploy_run(&env) == CLI_EXIT_VERIFY,
          "missing rollback tag exits 3");
    CHECK(f.published_count == 0, "no publish for a rollback");
    config_free(cfg);
}

static void test_existing_release_verify_failure_is_verify(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.rel_exists = 1;
    f.verify_rc = CLI_EXIT_VERIFY;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_VERIFY,
          "immutable-tag verification failure exits 3");
    CHECK(f.published_count == 0, "immutable tag never republished");
    config_free(cfg);
}

static void test_publish_failure_is_aws(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.publish_rc = EIO;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_AWS, "publish failure exits 2");
    CHECK(f.executed == 0, "no stack update after publish failure");
    config_free(cfg);
}

static void test_empty_change_set_skips_execute(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.rel_exists = 1;
    env = make_env(&f, cfg, &fx);
    f.change_count = 0;
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "empty change set succeeds");
    CHECK(f.executed == 0, "nothing executed");
    CHECK(f.confirm_calls == 0, "no prompt for an empty change set");
    CHECK(f.deleted_change_sets == 1, "change set deleted");
    config_free(cfg);
}

static void test_dry_run_deletes_change_set(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    env = make_env(&f, cfg, &fx);
    env.dry_run = 1;
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "dry-run succeeds");
    CHECK(f.executed == 0, "dry-run never executes");
    CHECK(f.deleted_change_sets == 1, "dry-run deletes its change set");
    config_free(cfg);
}

static void test_decline_and_noninteractive(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    env = make_env(&f, cfg, &fx);
    f.confirm_result = CLI_CONFIRM_NO;
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "decline is not an error");
    CHECK(f.executed == 0, "decline never executes");
    CHECK(f.deleted_change_sets == 1, "decline deletes the change set");
    config_free(cfg);

    fixture_init(&fx);
    cfg = load_config(&fx);
    env = make_env(&f, cfg, &fx);
    f.confirm_result = CLI_CONFIRM_NONINTERACTIVE;
    CHECK(deploy_run(&env) == CLI_EXIT_USAGE,
          "non-TTY without --yes exits 1");
    CHECK(f.executed == 0, "non-interactive never executes");
    config_free(cfg);
}

static void test_execute_failure_is_aws(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.execute_rc = EIO;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_AWS, "execute failure exits 2");
    CHECK(trace_index(&f, TRACE_WAIT_STACK) < 0, "no wait after failure");
    config_free(cfg);
}

static void test_idempotent_redeploy_uses_existing_release(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.rel_exists = 0;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "first deploy publishes");
    CHECK(f.published_count == 1, "one publish");
    config_free(cfg);

    /* Second run sees the now-immutable tag and takes the verify path. */
    f.published_count = 0;
    f.verified_count = 0;
    f.rel_exists = 1;
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.change_count = 0;
    cfg = load_config(&fx);
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "second deploy is idempotent");
    CHECK(f.published_count == 0, "immutable tag is not republished");
    CHECK(f.verified_count == 1, "existing manifest verified");
    config_free(cfg);
}

/* ------------------------------------------------------------------------- */
/* Publish read-back, prune, immutability, escaping                          */
/* ------------------------------------------------------------------------- */

static void test_skip_build_against_immutable_tag_is_verify(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.rel_exists = 1;
    env = make_env(&f, cfg, &fx);
    env.skip_build = 1;
    CHECK(deploy_run(&env) == CLI_EXIT_VERIFY,
          "--skip-build against an immutable tag exits 3");
    CHECK(f.executed == 0, "no stack update");
    config_free(cfg);
}

static void test_publish_readback_before_record(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.rel_exists = 0;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "new release deploy succeeds");
    CHECK(trace_index(&f, TRACE_PUBLISH) < trace_index(&f, TRACE_VERIFY),
          "publish read-back after upload");
    CHECK(trace_index(&f, TRACE_VERIFY) < trace_index(&f, TRACE_CREATE_CS),
          "read-back before recording on the stack");
    config_free(cfg);

    fixture_init(&fx);
    cfg = load_config(&fx);
    f = (fake){0};
    f.rel_exists = 0;
    f.verify_rc = CLI_EXIT_VERIFY;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_VERIFY,
          "read-back failure exits 3 before recording");
    CHECK(trace_index(&f, TRACE_CREATE_CS) < 0, "no stack mutation");
    config_free(cfg);
}

static void test_prune_runs_after_execute(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.rel_exists = 0;
    env = make_env(&f, cfg, &fx);
    snprintf(env.previous_tag, sizeof(env.previous_tag), "v1.0.0");
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "deploy with prune succeeds");
    CHECK(f.prune_calls == 1, "prune runs once");
    CHECK(trace_index(&f, TRACE_WAIT_STACK) < trace_index(&f, TRACE_PRUNE),
          "prune after the stack update");
    CHECK(strcmp(f.prune_uploaded, "v1.2.3") == 0, "just-uploaded protected");
    CHECK(strcmp(f.prune_previous, "v1.0.0") == 0, "previous tag protected");
    config_free(cfg);
}

static void test_prune_selection(void) {
    deploy_release_entry entries[14];
    long long now = 1700000000;

    memset(entries, 0, sizeof(entries));
    for (int i = 0; i < 12; i++) {
        snprintf(entries[i].tag, sizeof(entries[i].tag), "v1.0.%d", i + 1);
        entries[i].manifest_epoch = 1000 + i;
    }
    /* entries[12] is old manifest-less garbage; [13] is recent garbage. */
    snprintf(entries[12].tag, sizeof(entries[12].tag), "v9.9.9");
    entries[12].newest_epoch = now - 90000;
    snprintf(entries[13].tag, sizeof(entries[13].tag), "v9.9.8");
    entries[13].newest_epoch = now - 60;

    CHECK(deploy_prune_mark(entries, 14, NULL, NULL, NULL, now) == 3,
          "keeps 10 newest + deletes one old garbage prefix");
    CHECK(entries[0].delete_me == 1 && entries[1].delete_me == 1,
          "two oldest releases pruned");
    CHECK(entries[2].delete_me == 0 && entries[11].delete_me == 0,
          "ten newest releases kept");
    CHECK(entries[12].delete_me == 1, "manifest-less garbage older than 24h");
    CHECK(entries[13].delete_me == 0, "recent garbage kept");

    memset(entries, 0, sizeof(entries));
    for (int i = 0; i < 12; i++) {
        snprintf(entries[i].tag, sizeof(entries[i].tag), "v1.0.%d", i + 1);
        entries[i].manifest_epoch = 1000 + i;
    }
    /* Protection wins even for an old release. */
    CHECK(deploy_prune_mark(entries, 12, "v1.0.1", "v1.0.2", "v1.0.3", now) ==
              0,
          "protected old releases are kept");
}

static void test_manifest_line_sha_first(void) {
    char line[128];
    const char *sha =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    CHECK(deploy_manifest_line(sha, "bundle.tar", line, sizeof(line)) == 0,
          "manifest line formats");
    CHECK(strcmp(line,
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                 "aaaaaaaa  bundle.tar\n") == 0,
          "manifest is <sha>  <member>");
}

static void test_shell_quote_escapes(void) {
    char quoted[128];

    CHECK(deploy_shell_quote("/tmp/a'b c", quoted, sizeof(quoted)) == 0,
          "shell quote succeeds");
    CHECK(strcmp(quoted, "'/tmp/a'\\''b c'") == 0,
          "embedded single quote is escaped");
}

static void test_iso8601_parser(void) {
    long long epoch = 0;

    CHECK(deploy_iso8601_to_epoch("2024-01-02T03:04:05.000Z", &epoch) == 0,
          "S3 timestamp parses");
    CHECK(epoch > 1700000000, "timestamp is sane");
    CHECK(deploy_iso8601_to_epoch("not-a-date", &epoch) == EINVAL,
          "malformed timestamp rejected");
}

static void test_live_instance_count_queried(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.live_count = 2;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "deploy with live instances");
    CHECK(trace_index(&f, TRACE_LIVE) >= 0, "live count queried");
    CHECK(trace_index(&f, TRACE_LIVE) < trace_index(&f, TRACE_CREATE_CS),
          "live count before change-set preview");
    config_free(cfg);
}

static void put_param(cfn_parameter *p, const char *key, const char *value) {
    snprintf(p->key, sizeof(p->key), "%s", key);
    snprintf(p->value, sizeof(p->value), "%s", value);
}

static void test_param_diff_listing(void) {
    cfn_parameter old_params[3] = {0};
    cfn_parameter new_params[3] = {0};
    cfn_stack current = {0};
    char buf[1024];
    size_t got;
    size_t diffs;
    FILE *out;

    put_param(&old_params[0], "ProjectName", "demo");
    put_param(&old_params[1], "ReleaseTag", "v0.9.0");
    put_param(&old_params[2], "LegacyFlag", "on");
    current.parameters = old_params;
    current.parameter_count = 3;

    put_param(&new_params[0], "ProjectName", "demo");   /* unchanged */
    put_param(&new_params[1], "ReleaseTag", "v1.2.3");  /* changed */
    put_param(&new_params[2], "AmiIdAmd64", "ami-new"); /* added */

    out = tmpfile();
    CHECK(out != NULL, "diff sink opens");
    if (out == NULL) {
        return;
    }
    diffs = deploy_param_diff_write(out, &current, new_params, 3);
    fflush(out);
    rewind(out);
    got = fread(buf, 1, sizeof(buf) - 1, out);
    buf[got] = '\0';
    fclose(out);

    CHECK(diffs == 3, "three parameter differences");
    CHECK(strstr(buf, "parameter changes:") != NULL, "diff header present");
    CHECK(strstr(buf, "ReleaseTag: Changed: v0.9.0 -> v1.2.3") != NULL,
          "changed parameter listed old -> new");
    CHECK(strstr(buf, "AmiIdAmd64: Added = ami-new") != NULL,
          "added parameter listed");
    CHECK(strstr(buf, "LegacyFlag: Removed = on") != NULL,
          "removed parameter listed");
    CHECK(strstr(buf, "ProjectName") == NULL,
          "unchanged parameter not listed");
}

static void test_json_preview_has_structured_param_diff(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;
    char buf[8192];
    size_t got;
    FILE *sink;
    yyjson_doc *doc;
    yyjson_val *root;
    yyjson_val *arr;
    yyjson_val *entry;
    int saw_changed = 0;
    int saw_removed = 0;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.rel_exists = 1;
    f.change_count = 2;
    f.old_param_count = 2;
    snprintf(f.old_param_keys[0], sizeof(f.old_param_keys[0]), "%s",
             "ReleaseTag");
    snprintf(f.old_param_values[0], sizeof(f.old_param_values[0]), "%s",
             "v0.9.0");
    snprintf(f.old_param_keys[1], sizeof(f.old_param_keys[1]), "%s",
             "LegacyFlag");
    snprintf(f.old_param_values[1], sizeof(f.old_param_values[1]), "%s", "on");

    env = make_env(&f, cfg, &fx);
    env.tag_arg = "v1.0.0";
    env.json = 1;
    env.dry_run = 1;
    sink = tmpfile();
    CHECK(sink != NULL, "json sink opens");
    if (sink == NULL) {
        config_free(cfg);
        return;
    }
    env.out = sink;
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "json dry-run deploy succeeds");
    fflush(sink);
    rewind(sink);
    got = fread(buf, 1, sizeof(buf) - 1, sink);
    buf[got] = '\0';
    fclose(sink);

    doc = yyjson_read(buf, got, 0);
    CHECK(doc != NULL, "deploy --json output is valid JSON");
    if (doc != NULL) {
        root = yyjson_doc_get_root(doc);
        arr = yyjson_obj_get(root, "parameter_diff");
        CHECK(yyjson_is_arr(arr), "parameter_diff is a JSON array");
        if (yyjson_is_arr(arr)) {
            yyjson_arr_iter iter = yyjson_arr_iter_with(arr);

            while ((entry = yyjson_arr_iter_next(&iter)) != NULL) {
                const char *name = yyjson_get_str(yyjson_obj_get(entry, "name"));
                const char *action =
                    yyjson_get_str(yyjson_obj_get(entry, "action"));

                if (name != NULL && strcmp(name, "ReleaseTag") == 0 &&
                    action != NULL && strcmp(action, "Changed") == 0) {
                    const char *old_v =
                        yyjson_get_str(yyjson_obj_get(entry, "old"));
                    const char *new_v =
                        yyjson_get_str(yyjson_obj_get(entry, "new"));

                    if (old_v != NULL && strcmp(old_v, "v0.9.0") == 0 &&
                        new_v != NULL && strcmp(new_v, "v1.0.0") == 0) {
                        saw_changed = 1;
                    }
                }
                if (name != NULL && strcmp(name, "LegacyFlag") == 0 &&
                    action != NULL && strcmp(action, "Removed") == 0) {
                    saw_removed = 1;
                }
            }
        }
        yyjson_doc_free(doc);
    }
    CHECK(saw_changed, "JSON diff records changed ReleaseTag old -> new");
    CHECK(saw_removed, "JSON diff records removed parameter");
    config_free(cfg);
}

/* ------------------------------------------------------------------------- */
/* TEMPLATE_OVERRIDE and AMI policy                                          */
/* ------------------------------------------------------------------------- */

static void test_template_override_valid_is_used_and_checked(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    fixture_install_override(&fx, "deploy/custom.yaml",
                             "deploy/stackctl-infra.yaml",
                             "# override-marker\n");
    fixture_append_env(&fx, "TEMPLATE_OVERRIDE=deploy/custom.yaml\n");
    cfg = load_config(&fx);
    f.read_templates = 1;
    f.stack_present = 0;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK,
          "valid TEMPLATE_OVERRIDE deploy succeeds");
    CHECK(strstr(f.last_template, "override-marker") != NULL,
          "override template is used in the change-set body");
    CHECK(trace_index(&f, TRACE_TEMPLATE) < trace_index(&f, TRACE_BUCKET),
          "template load and check before bucket preflight");
    config_free(cfg);
}

static void test_template_override_invalid_aborts_before_aws(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;
    FILE *errors;
    char captured[4096];
    size_t got;
    int saved_stderr;
    int rc;

    fixture_init(&fx);
    fixture_install_override(&fx, "deploy/bad.yaml",
                             "deploy/check/testdata/bad_infra_bucket.yaml",
                             NULL);
    fixture_append_env(&fx, "TEMPLATE_OVERRIDE=deploy/bad.yaml\n");
    cfg = load_config(&fx);
    f.read_templates = 1;
    env = make_env(&f, cfg, &fx);
    errors = tmpfile();
    CHECK(errors != NULL, "stderr capture opens");
    if (errors == NULL) {
        config_free(cfg);
        return;
    }
    saved_stderr = dup(STDERR_FILENO);
    CHECK(saved_stderr >= 0, "stderr can be duplicated");
    (void)dup2(fileno(errors), STDERR_FILENO);
    rc = deploy_run(&env);
    fflush(stderr);
    if (saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    rewind(errors);
    got = fread(captured, 1, sizeof(captured) - 1, errors);
    captured[got] = '\0';
    fclose(errors);

    CHECK(rc == CLI_EXIT_USAGE, "invalid override exits usage (1)");
    CHECK(trace_index(&f, TRACE_BUCKET) < 0, "no bucket preflight");
    CHECK(trace_index(&f, TRACE_AMI_RESOLVE) < 0, "no AMI preflight");
    CHECK(trace_index(&f, TRACE_AWS_INIT) < 0, "no AWS init");
    CHECK(trace_index(&f, TRACE_CREATE_CS) < 0, "no change set");
    CHECK(f.published_count == 0, "nothing published");
    CHECK(strstr(captured, "DeletionPolicy") != NULL,
          "violation is named in stderr");
    CHECK(strstr(captured, "bad.yaml") != NULL, "filename is named in stderr");
    config_free(cfg);
}

static void test_no_override_uses_canonical_template(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;

    fixture_init(&fx);
    fixture_install_canonical(&fx);
    cfg = load_config(&fx);
    f.read_templates = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "canonical template deploy succeeds");
    CHECK(strncmp(f.last_template, "AWSTemplateFormatVersion", 24) == 0,
          "canonical template is used in the change-set body");
    config_free(cfg);
}

static void test_ami_params_only_when_pinned(void) {
    static const char *ssm_env =
        "PROJECT=demo\n"
        "REGION=us-east-1\n"
        "ARCH=amd64\n"
        "SPOT_DEFAULT=false\n"
        "AMI_POLICY=ssm\n"
        "AMI_SSM_AMD64=/aws/service/ami-amazon-linux-latest/al2023-ami\n"
        "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"
        "ROOT_VOLUME_SIZE=100\n"
        "KEY_NAME=demo-key\n"
        "SSH_IDENTITY=/home/operator/.ssh/demo\n"
        "BUCKET_MODULES=artifact,cert\n"
        "ENABLE_IMAGE_BUILDER=false\n"
        "SETUP_ENTRYPOINT=deploy.sh\n"
        "SSH_PORT=22\n"
        "OPERATOR_CIDR=203.0.113.0/24\n"
        "INGRESS_TCP=443\n"
        "INGRESS_UDP=\n"
        "RELEASE_TARGETS=//app:deploy.tar.gz\n"
        "RELEASE_PREFIXES=releases/\n";
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    deploy_env env;
    int ami_param = 0;
    int policy_param = 0;

    fixture_init(&fx);
    fixture_write_env(&fx, ssm_env);
    cfg = load_config(&fx);
    CHECK(cfg != NULL, "ssm config loads");
    if (cfg == NULL) {
        return;
    }
    env = make_env(&f, cfg, &fx);
    CHECK(deploy_run(&env) == CLI_EXIT_OK, "ssm deploy succeeds");
    for (size_t i = 0; i < f.last_param_count && i < 16; i++) {
        if (strncmp(f.params[i], "AmiId", 5) == 0) {
            ami_param = 1;
        }
        if (strcmp(f.params[i], "AmiPolicy") == 0) {
            policy_param = strcmp(f.param_values[i], "ssm") == 0;
        }
    }
    CHECK(ami_param == 0, "non-pinned deploy passes no AmiId parameters");
    CHECK(policy_param, "AmiPolicy parameter is ssm");
    config_free(cfg);
}

static char *make_credentials_home(void) {
    char *home = strdup("/tmp/stackctl-abort-XXXXXX");
    char dir[PATH_MAX];
    char path[PATH_MAX];
    FILE *file;

    if (home == NULL || mkdtemp(home) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    if (snprintf(dir, sizeof dir, "%s/.aws", home) >= (int)sizeof dir ||
        mkdir(dir, 0700) != 0) {
        perror("mkdir .aws");
        exit(2);
    }
    if (snprintf(path, sizeof path, "%s/credentials", dir) >= (int)sizeof path) {
        exit(2);
    }
    file = fopen(path, "w");
    if (file == NULL) {
        perror("fopen credentials");
        exit(2);
    }
    fputs("[prod-abort]\n"
          "aws_access_key_id = AKIAFAKEFAKEFAKEFAKE\n"
          "aws_secret_access_key = fake-secret\n",
          file);
    if (fclose(file) != 0) {
        exit(2);
    }
    return home;
}

static void test_prod_aws_init_installs_abort_hook(void) {
    char *home = make_credentials_home();
    const char *saved_home = getenv("HOME");
    char *saved = saved_home != NULL ? strdup(saved_home) : NULL;
    aws_ctx *aws = NULL;
    int rc;

    CHECK(setenv("HOME", home, 1) == 0, "HOME points at fake credentials");
    rc = deploy_prod_aws_init_for_test("prod-abort", &aws);
    CHECK(rc == 0, "production aws_init succeeds");
    if (rc == 0) {
        CHECK(aws != NULL, "production aws_init returns a client");
        CHECK(aws != NULL && aws->abort_fn == cli_abort_check,
              "production aws_init installs the CLI abort hook");
        CHECK(aws != NULL && aws->abort_ud == NULL,
              "abort hook has no user data");
    }
    aws_free(aws);
    if (saved != NULL) {
        CHECK(setenv("HOME", saved, 1) == 0, "HOME restored");
        free(saved);
    } else {
        unsetenv("HOME");
    }
}

int main(void) {
    test_prod_aws_init_installs_abort_hook();
    test_null_env();
    test_provenance_failure();
    test_ambiguous_tag_is_usage();
    test_freshness_failure_is_6();
    test_skip_build_bypasses_freshness();
    test_ami_preflight_failure_is_usage();
    test_in_progress_stack_is_aws();
    test_stack_state_recovery_guidance();
    test_new_release_publishes_then_updates_in_order();
    test_update_tags_release_identity();
    test_rollback_existing_tag_skips_gates_and_publish();
    test_rollback_missing_tag_is_verify();
    test_existing_release_verify_failure_is_verify();
    test_publish_failure_is_aws();
    test_empty_change_set_skips_execute();
    test_dry_run_deletes_change_set();
    test_decline_and_noninteractive();
    test_execute_failure_is_aws();
    test_idempotent_redeploy_uses_existing_release();
    test_skip_build_against_immutable_tag_is_verify();
    test_publish_readback_before_record();
    test_prune_runs_after_execute();
    test_prune_selection();
    test_manifest_line_sha_first();
    test_shell_quote_escapes();
    test_iso8601_parser();
    test_live_instance_count_queried();
    test_param_diff_listing();
    test_json_preview_has_structured_param_diff();
    test_template_override_valid_is_used_and_checked();
    test_template_override_invalid_aborts_before_aws();
    test_no_override_uses_canonical_template();
    test_ami_params_only_when_pinned();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("deploy_test: ok\n");
    return 0;
}
