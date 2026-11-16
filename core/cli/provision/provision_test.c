/*
 * provision_test.c — orchestration tests for `stackctl provision`.
 *
 * Every AWS-bound step is a fake vtable entry, so the tests assert the exact
 * order of operations (describe -> create change set -> wait -> describe ->
 * execute -> wait) plus the confirmation, dry-run, empty-change-set, status and
 * failure semantics of spec §4. No credentials or network are involved.
 */

#include "provision_internal.h"

#include "aws_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ------------------------------------------------------------------------- */
/* Trace                                                                     */
/* ------------------------------------------------------------------------- */

enum trace_tag {
    TRACE_AWS_INIT = 1,
    TRACE_CFN_CREATE,
    TRACE_TEMPLATE,
    TRACE_DESCRIBE,
    TRACE_CREATE_CS,
    TRACE_WAIT_CS,
    TRACE_DESC_CS,
    TRACE_EXECUTE,
    TRACE_WAIT_STACK,
    TRACE_DELETE_CS,
    TRACE_DELETE_STACK,
    TRACE_KEYS,
    TRACE_LIST,
    TRACE_CREATE_KEY,
    TRACE_DELETE_KEY,
    TRACE_WRITE_CRED,
    TRACE_CRED_READ,
    TRACE_IDENTITY
};

typedef struct fake {
    int trace[64];
    int trace_count;

    int aws_init_rc;
    int cfn_create_rc;
    int read_rc;
    int read_templates;
    int stack_present;
    cfn_stack_status status;
    int create_rc;
    int wait_cs_rc;
    int wait_cs_no_changes;
    int describe_cs_rc;
    int change_count;
    int execute_rc;
    int wait_stack_rc;
    int delete_cs_rc;
    int delete_stack_rc;
    int keys_rc;
    int identity_mismatch;

    int list_rc;
    int key_create_rc;
    int delete_rc;
    int write_rc;
    int op_key_count;
    char op_key_ids[4][64];
    int ci_key_count;
    char ci_key_ids[4][64];
    int have_local_op;
    char local_op_key[64];
    int have_local_ci;
    char local_ci_key[64];
    int create_count;
    int delete_count;
    char deleted_ids[16][64];
    int write_count;
    char written_key[64];
    char written_secret[64];
    int identity_attempts;
    int identity_eacces_attempts;

    int last_type;
    unsigned last_caps;
    char last_stack[128];
    size_t last_param_count;
    char params[12][128];
    char param_values[12][256];

    /* When non-NULL, the described stack exposes this CiUserName output. */
    const char *ci_output;

    int executed;
    int deleted_change_sets;
    int deleted_stacks;
    int delete_stack_calls;
    int keys_rotate;
    int keys_rotate_ci;
    int confirm_calls;
    int confirm_result;
} fake;


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

/* ------------------------------------------------------------------------- */
/* Fake vtable                                                               */
/* ------------------------------------------------------------------------- */

static int fake_aws_init(void *ud, const char *profile, aws_ctx **out) {
    fake *f = ud;

    (void)profile;
    trace(f, TRACE_AWS_INIT);
    *out = (aws_ctx *)f; /* opaque, only round-tripped */
    return f->aws_init_rc;
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
    return f->cfn_create_rc;
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
    if (f->ci_output != NULL) {
        out->items[0].outputs = calloc(1, sizeof(*out->items[0].outputs));
        if (out->items[0].outputs == NULL) {
            return ENOMEM;
        }
        out->items[0].output_count = 1;
        snprintf(out->items[0].outputs[0].key,
                 sizeof(out->items[0].outputs[0].key), "CiUserName");
        snprintf(out->items[0].outputs[0].value,
                 sizeof(out->items[0].outputs[0].value), "%s", f->ci_output);
    }
    return 0;
}

static void fake_stack_list_free(void *ud, cfn_stack_list *list) {
    (void)ud;
    if (list != NULL) {
        if (list->items != NULL) {
            free(list->items[0].outputs);
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
    f->last_param_count = spec->parameter_count;
    for (size_t i = 0; i < spec->parameter_count && i < 8; i++) {
        snprintf(f->params[i], sizeof(f->params[i]), "%s",
                 spec->parameters[i].key);
        snprintf(f->param_values[i], sizeof(f->param_values[i]), "%s",
                 spec->parameters[i].value);
    }
    snprintf(out->change_set_id, sizeof(out->change_set_id), "cs-1");
    snprintf(out->stack_id, sizeof(out->stack_id), "stack-1");
    return f->create_rc;
}

static int fake_wait_cs(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs, int attempts,
                        int interval, int *timed_out, int *no_changes) {
    fake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    (void)attempts;
    (void)interval;
    trace(f, TRACE_WAIT_CS);
    if (timed_out != NULL) {
        *timed_out = 0;
    }
    if (no_changes != NULL) {
        *no_changes = f->wait_cs_no_changes;
    }
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
    if (timed_out != NULL) {
        *timed_out = 0;
    }
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
    f->delete_stack_calls++;
    return f->delete_stack_rc;
}

static int fake_iam_identity(void *ud, aws_ctx *ctx, char **out_arn) {
    fake *f = ud;

    (void)ctx;
    trace(f, TRACE_IDENTITY);
    f->identity_attempts++;
    if (f->identity_attempts <= f->identity_eacces_attempts) {
        return EACCES;
    }
    *out_arn = strdup(f->identity_mismatch ? "arn:aws:iam::123:user/other"
                                           : "arn:aws:iam::123:user/demo");
    return *out_arn != NULL ? 0 : ENOMEM;
}

static int fake_iam_list(void *ud, aws_ctx *ctx, const char *user,
                         iam_key **out, size_t *out_count) {
    fake *f = ud;
    int is_ci = user != NULL && strstr(user, "-ci") != NULL;
    int count = is_ci ? f->ci_key_count : f->op_key_count;

    (void)ctx;
    trace(f, TRACE_LIST);
    if (f->list_rc != 0) {
        return f->list_rc;
    }
    *out = NULL;
    *out_count = 0;
    if (count == 0) {
        return 0;
    }
    *out = calloc((size_t)count, sizeof(**out));
    if (*out == NULL) {
        return ENOMEM;
    }
    for (int i = 0; i < count; i++) {
        const char *id = is_ci ? f->ci_key_ids[i] : f->op_key_ids[i];
        (*out)[i].user_name = strdup(is_ci ? "demo-ci" : "demo");
        (*out)[i].access_key_id = strdup(id);
        (*out)[i].status = strdup("Active");
    }
    *out_count = (size_t)count;
    return 0;
}

static int fake_iam_create(void *ud, aws_ctx *ctx, const char *user,
                           iam_key *out) {
    fake *f = ud;
    char id[64];

    (void)ctx;
    trace(f, TRACE_CREATE_KEY);
    f->create_count++;
    snprintf(id, sizeof(id), "AKIANEW%d", f->create_count);
    out->user_name = strdup(user != NULL ? user : "demo");
    out->access_key_id = strdup(id);
    out->secret_access_key = strdup("SECRETNEW");
    out->status = strdup("Active");
    return f->key_create_rc;
}

static int fake_iam_delete(void *ud, aws_ctx *ctx, const char *user,
                           const char *key_id) {
    fake *f = ud;

    (void)ctx;
    (void)user;
    trace(f, TRACE_DELETE_KEY);
    if (f->delete_count < (int)(sizeof(f->deleted_ids) / sizeof(f->deleted_ids[0]))) {
        snprintf(f->deleted_ids[f->delete_count], sizeof(f->deleted_ids[0]), "%s",
                 key_id);
    }
    f->delete_count++;
    return f->delete_rc;
}

static void fake_iam_key_free(void *ud, iam_key *key) {
    (void)ud;
    free(key->user_name);
    free(key->access_key_id);
    free(key->secret_access_key);
    free(key->status);
    free(key->create_date);
    memset(key, 0, sizeof(*key));
}

static void fake_iam_keys_free(void *ud, iam_key *keys, size_t count) {
    (void)ud;
    if (keys == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(keys[i].user_name);
        free(keys[i].access_key_id);
        free(keys[i].secret_access_key);
        free(keys[i].status);
        free(keys[i].create_date);
    }
    free(keys);
}

static int fake_credentials_key_id(void *ud, const char *profile, char **out) {
    fake *f = ud;
    int is_ci = strstr(profile, "-ci") != NULL;

    trace(f, TRACE_CRED_READ);
    *out = NULL;
    if (is_ci && f->have_local_ci) {
        *out = strdup(f->local_ci_key);
    } else if (!is_ci && f->have_local_op) {
        *out = strdup(f->local_op_key);
    }
    return 0;
}

static int fake_credentials_write(void *ud, const char *profile,
                                  const char *key_id, const char *secret,
                                  char **backup_out) {
    fake *f = ud;

    (void)profile;
    trace(f, TRACE_WRITE_CRED);
    f->write_count++;
    snprintf(f->written_key, sizeof(f->written_key), "%s", key_id);
    snprintf(f->written_secret, sizeof(f->written_secret), "%s", secret);
    if (backup_out != NULL) {
        *backup_out = NULL;
    }
    return f->write_rc;
}

static void fake_retry_pause(void *ud) { (void)ud; }

static int fake_template(void *ud, const char *repo_root, char **body_out) {
    fake *f = ud;

    (void)repo_root;
    trace(f, TRACE_TEMPLATE);
    if (f->read_rc != 0) {
        return f->read_rc;
    }
    *body_out = strdup("Resources: {}\n");
    return *body_out != NULL ? 0 : ENOMEM;
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
    body[size] = '\0';
    fclose(file);
    *body_out = body;
    return 0;
}

static const provision_ops fake_ops = {
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
    .iam_identity = fake_iam_identity,
    .iam_list_keys = fake_iam_list,
    .iam_create_key = fake_iam_create,
    .iam_delete_key = fake_iam_delete,
    .iam_key_free = fake_iam_key_free,
    .iam_keys_free = fake_iam_keys_free,
    .credentials_key_id = fake_credentials_key_id,
    .credentials_write = fake_credentials_write,
    .retry_pause = fake_retry_pause,
    .read_template = fake_template,
};

/* Path-loading variant used by the §6.3 template-gate cases; the base fake
 * keeps the path seam NULL so the orchestration cases stay filesystem-free. */
static provision_ops configured_ops;

/* ------------------------------------------------------------------------- */
/* Fixtures                                                                  */
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

static void fixture_init(fixture *fx) {
    char template[] = "/tmp/stackctl-provision-XXXXXX";
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

/*
 * Rewrite the fixture `.env` with one literal substitution applied to the
 * shared base environment, so a single key can be changed per case.
 */
static void fixture_env_with(fixture *fx, const char *needle,
                             const char *replacement) {
    const char *at = strstr(base_env, needle);
    char path[PATH_MAX];
    char buffer[4096];
    int written;

    if (at == NULL) {
        fprintf(stderr, "fixture base env lacks %s\n", needle);
        exit(1);
    }
    written = snprintf(buffer, sizeof(buffer), "%.*s%s%s",
                       (int)(at - base_env), base_env, replacement,
                       at + strlen(needle));
    if (written < 0 || (size_t)written >= sizeof(buffer)) {
        fprintf(stderr, "fixture env replacement overflows\n");
        exit(1);
    }
    snprintf(path, sizeof(path), "%s/.env", fx->config_dir);
    write_text(path, buffer);
}

/* Return the captured parameter value for `key`, or NULL when absent. */
static const char *captured_param(const fake *f, const char *key) {
    for (size_t i = 0; i < f->last_param_count && i < 12; i++) {
        if (strcmp(f->params[i], key) == 0) {
            return f->param_values[i];
        }
    }
    return NULL;
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

static void fixture_write_operator(fixture *fx, const char *body) {
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/deploy/stackctl-operator.yaml", fx->root);
    write_text(path, body);
}

static void fixture_install_operator(fixture *fx) {
    char *text = read_runfile("deploy/stackctl-operator.yaml");

    if (text == NULL) {
        fprintf(stderr, "cannot load the canonical operator template\n");
        exit(1);
    }
    fixture_write_operator(fx, text);
    free(text);
}

/*
 * Install the canonical operator template with an extra policy whose wildcard
 * action violates §6.3, giving the gate a deterministic failure to report.
 */
static void fixture_install_tampered_operator(fixture *fx) {
    static const char insertion[] =
        "  TamperedPolicy:\n"
        "    Type: AWS::IAM::ManagedPolicy\n"
        "    Properties:\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Action: \"*\"\n"
        "            Resource: \"*\"\n";
    char *text = read_runfile("deploy/stackctl-operator.yaml");
    const char *anchor;
    size_t prefix_len;
    size_t combined;
    char *tampered;

    if (text == NULL) {
        fprintf(stderr, "cannot load the canonical operator template\n");
        exit(1);
    }
    anchor = strstr(text, "Resources:\n");
    if (anchor == NULL) {
        fprintf(stderr, "canonical operator template lacks Resources\n");
        free(text);
        exit(1);
    }
    prefix_len = (size_t)(anchor - text) + strlen("Resources:\n");
    combined = strlen(text) + sizeof(insertion);
    tampered = malloc(combined);
    if (tampered == NULL) {
        free(text);
        exit(1);
    }
    memcpy(tampered, text, prefix_len);
    memcpy(tampered + prefix_len, insertion, sizeof(insertion) - 1);
    strcpy(tampered + prefix_len + sizeof(insertion) - 1, text + prefix_len);
    fixture_write_operator(fx, tampered);
    free(tampered);
    free(text);
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

static provision_env make_env(fake *f, stackctl_config *cfg, fixture *fx) {
    provision_env env = {0};

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
    f->confirm_result = CLI_CONFIRM_YES;
    return env;
}

/* ------------------------------------------------------------------------- */
/* Cases                                                                     */
/* ------------------------------------------------------------------------- */

static void test_null_context(void) {
    CHECK(cli_cmd_provision(NULL) == CLI_EXIT_USAGE, "NULL ctx is usage");
}

static void test_region_variant_rejected(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    CHECK(cfg != NULL, "config loads");
    env = make_env(&f, cfg, &fx);
    env.region_variant = 1;
    CHECK(provision_run(&env) == CLI_EXIT_USAGE,
          "provision is primary-config only");
    CHECK(f.trace_count == 0, "no AWS call before the region check");
    config_free(cfg);
}

static void test_template_failure_is_usage(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.read_rc = ENOENT;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_USAGE, "missing template is usage");
    CHECK(f.executed == 0, "nothing executed");
    config_free(cfg);
}

static void test_in_progress_stack_exits_2(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_IN_PROGRESS;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_AWS,
          "in-progress stack is an AWS-class failure");
    CHECK(trace_index(&f, TRACE_CREATE_CS) < 0,
          "no change set while another operation is in progress");
    config_free(cfg);
}

static void test_rollback_complete_exits_2(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_ROLLBACK_COMPLETE;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_AWS,
          "failed-create rollback is an AWS-class failure");
    CHECK(trace_index(&f, TRACE_CREATE_CS) < 0, "no change set");
    config_free(cfg);
}

static void test_create_path_executes_in_order(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 3;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "create path succeeds");
    CHECK(f.last_stack[0] != '\0' && strcmp(f.last_stack, "demo-operator") == 0,
          "operator stack name");
    CHECK(f.last_type == CFN_CHANGE_SET_TYPE_CREATE, "CREATE change set");
    CHECK((f.last_caps & CFN_CAPABILITY_NAMED_IAM) != 0, "named IAM capability");
    CHECK(f.executed == 1, "change set executed once");
    CHECK(trace_index(&f, TRACE_DESCRIBE) < trace_index(&f, TRACE_CREATE_CS),
          "describe before create");
    CHECK(trace_index(&f, TRACE_CREATE_CS) < trace_index(&f, TRACE_WAIT_CS),
          "create before wait");
    CHECK(trace_index(&f, TRACE_WAIT_CS) < trace_index(&f, TRACE_DESC_CS),
          "wait before describe change set");
    CHECK(trace_index(&f, TRACE_DESC_CS) < trace_index(&f, TRACE_EXECUTE),
          "describe before execute");
    CHECK(trace_index(&f, TRACE_EXECUTE) < trace_index(&f, TRACE_WAIT_STACK),
          "execute before stack wait");
    CHECK(f.create_count == 2, "operator and CI keys minted");
    CHECK(f.write_count == 2, "both profiles written");
    config_free(cfg);
}

static void test_update_path_uses_update_change_set(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    env.rotate = 1;
    env.rotate_ci = 1;
    CHECK(provision_run(&env) == CLI_EXIT_OK, "update path succeeds");
    CHECK(f.last_type == CFN_CHANGE_SET_TYPE_UPDATE, "UPDATE change set");
    CHECK(f.create_count == 2, "rotation mints fresh keys");
    config_free(cfg);
}

static void test_dry_run_deletes_change_set(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 2;
    env = make_env(&f, cfg, &fx);
    env.dry_run = 1;
    CHECK(provision_run(&env) == CLI_EXIT_OK, "dry-run succeeds");
    CHECK(f.executed == 0, "dry-run never executes");
    CHECK(f.deleted_change_sets == 1, "dry-run deletes its change set");
    config_free(cfg);
}

static void test_decline_deletes_change_set(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 2;
    env = make_env(&f, cfg, &fx);
    f.confirm_result = CLI_CONFIRM_NO;
    CHECK(provision_run(&env) == CLI_EXIT_OK, "decline is not an error");
    CHECK(f.executed == 0, "decline never executes");
    CHECK(f.deleted_change_sets == 1, "decline deletes the change set");
    CHECK(f.confirm_calls == 1, "prompted once");
    config_free(cfg);
}

static void test_noninteractive_without_yes_is_usage(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 2;
    env = make_env(&f, cfg, &fx);
    f.confirm_result = CLI_CONFIRM_NONINTERACTIVE;
    CHECK(provision_run(&env) == CLI_EXIT_USAGE,
          "non-TTY without --yes exits 1");
    CHECK(f.executed == 0, "nothing executed");
    CHECK(f.deleted_change_sets == 1, "change set cleaned up");
    config_free(cfg);
}

static void test_empty_change_set_skips_prompt_and_execute(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_CREATE_COMPLETE;
    f.change_count = 0;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "empty change set succeeds");
    CHECK(f.executed == 0, "nothing executed");
    CHECK(f.confirm_calls == 0, "empty change set skips the prompt");
    CHECK(f.deleted_change_sets == 1, "empty change set deleted");
    config_free(cfg);
}

/* The operator's exact pilot scenario: the stack already conforms, so AWS
 * reports the change set FAILED with the "didn't contain changes" reason. The
 * stack step is a success and the key lifecycle still runs (0 keys -> mint). */
static void test_conforming_stack_still_runs_key_lifecycle(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.wait_cs_no_changes = 1;
    f.change_count = 0;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK,
          "no-changes provision completes");
    CHECK(f.executed == 0, "no-changes change set is never executed");
    CHECK(f.deleted_change_sets == 1, "no-changes change set deleted");
    CHECK(trace_index(&f, TRACE_LIST) >= 0, "key lifecycle ran");
    CHECK(trace_index(&f, TRACE_CREATE_KEY) >= 0, "keys minted");
    CHECK(f.create_count == 2, "operator and CI keys minted");
    CHECK(f.write_count == 2, "both profiles written");
    config_free(cfg);
}

static void test_execute_failure_is_aws(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 1;
    f.execute_rc = EIO;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_AWS, "execute failure exits 2");
    CHECK(trace_index(&f, TRACE_WAIT_STACK) < 0,
          "no stack wait after execute failure");
    config_free(cfg);
}

static void test_wait_stack_failure_is_aws(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 1;
    f.wait_stack_rc = ECANCELED;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_AWS, "stack failure exits 2");
    config_free(cfg);
}

static void test_identity_mismatch_is_verify(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 1;
    f.identity_mismatch = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_VERIFY,
          "identity guard failure exits 3");
    config_free(cfg);
}

static void test_union_of_region_variants(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    char path[PATH_MAX];
    int saw = 0;

    fixture_init(&fx);
    snprintf(path, sizeof(path), "%s/.env.eu-west-1", fx.config_dir);
    write_text(path,
               "# Region variant parsed by the config envfile rules.\n"
               "REGION=eu-west-1\n"
               "export INSTANCE_TYPES_AMD64=g6.xlarge\n"
               "BUCKET_MODULES=artifact\n"
               "ENABLE_IMAGE_BUILDER=true\n"
               "RELEASE_PREFIXES=releases/\n");
    cfg = load_config(&fx);
    CHECK(cfg != NULL, "primary config loads beside a variant");
    f.stack_present = 0;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "union run succeeds");
    for (size_t i = 0; i < f.last_param_count; i++) {
        if (strcmp(f.params[i], "InstanceTypeAllowlist") == 0) {
            saw = 1;
            CHECK(strstr(f.param_values[i], "g4dn.xlarge") != NULL,
                  "primary instance type present");
            CHECK(strstr(f.param_values[i], "g6.xlarge") != NULL,
                  "variant instance type unioned");
        }
    }
    CHECK(saw, "InstanceTypeAllowlist parameter present");
    config_free(cfg);
}

/* ------------------------------------------------------------------------- */
/* Operator parameters (F5 / F6 / F13)                                       */
/* ------------------------------------------------------------------------- */

static void test_ci_user_enabled_with_prefixes(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    const char *ci;
    const char *prefixes;
    const char *certs;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.stack_present = 0;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "prefixes run succeeds");
    ci = captured_param(&f, "EnableCiUser");
    prefixes = captured_param(&f, "ReleasePrefixes");
    certs = captured_param(&f, "CertBucketEnabled");
    CHECK(ci != NULL && strcmp(ci, "true") == 0,
          "EnableCiUser=true with prefixes");
    CHECK(prefixes != NULL && strcmp(prefixes, "releases/") == 0,
          "ReleasePrefixes passed with prefixes");
    CHECK(certs != NULL && strcmp(certs, "true") == 0,
          "CertBucketEnabled=true when cert module present");
    CHECK(captured_param(&f, "PermissionsBoundaryArn") == NULL,
          "PermissionsBoundaryArn absent when unset");
    config_free(cfg);
}

static void test_ci_user_disabled_without_prefixes(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    const char *ci;

    fixture_init(&fx);
    fixture_env_with(&fx, "RELEASE_PREFIXES=releases/", "RELEASE_PREFIXES=");
    cfg = load_config(&fx);
    CHECK(cfg != NULL, "empty-prefix config loads");
    f.stack_present = 0;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "empty-prefix run succeeds");
    ci = captured_param(&f, "EnableCiUser");
    CHECK(ci != NULL && strcmp(ci, "false") == 0,
          "EnableCiUser=false when prefixes empty");
    CHECK(captured_param(&f, "ReleasePrefixes") == NULL,
          "ReleasePrefixes omitted when prefixes empty");
    config_free(cfg);
}

static void test_ci_user_removal_warns(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    FILE *errors;
    char captured[2048];
    size_t got;

    fixture_init(&fx);
    fixture_env_with(&fx, "RELEASE_PREFIXES=releases/", "RELEASE_PREFIXES=");
    cfg = load_config(&fx);
    errors = tmpfile();
    CHECK(cfg != NULL && errors != NULL, "warning fixture opens");
    if (cfg == NULL || errors == NULL) {
        config_free(cfg);
        if (errors != NULL) {
            fclose(errors);
        }
        return;
    }
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.ci_output = "demo-ci";
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    env.err = errors;
    CHECK(provision_run(&env) == CLI_EXIT_OK, "CI removal run succeeds");
    rewind(errors);
    got = fread(captured, 1, sizeof(captured) - 1, errors);
    captured[got] = '\0';
    fclose(errors);
    CHECK(strstr(captured, "CiUser") != NULL,
          "removal warning names the CiUser deletion");
    CHECK(strstr(captured, "access keys") != NULL,
          "removal warning names key invalidation");
    config_free(cfg);
}

static void test_cert_bucket_disabled_without_cert_module(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    const char *certs;

    fixture_init(&fx);
    fixture_env_with(&fx, "BUCKET_MODULES=artifact,cert",
                     "BUCKET_MODULES=artifact");
    cfg = load_config(&fx);
    CHECK(cfg != NULL, "artifact-only config loads");
    f.stack_present = 0;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "artifact-only run succeeds");
    certs = captured_param(&f, "CertBucketEnabled");
    CHECK(certs != NULL && strcmp(certs, "false") == 0,
          "CertBucketEnabled=false without cert module");
    config_free(cfg);
}

static void test_permissions_boundary_passed_when_set(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    const char *arn;

    fixture_init(&fx);
    fixture_env_with(&fx, "RELEASE_PREFIXES=releases/",
                     "RELEASE_PREFIXES=releases/\n"
                     "PERMISSIONS_BOUNDARY_ARN=arn:aws:iam::123456789012:"
                     "policy/stackctl-boundary");
    cfg = load_config(&fx);
    CHECK(cfg != NULL, "boundary config loads");
    f.stack_present = 0;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK, "boundary run succeeds");
    arn = captured_param(&f, "PermissionsBoundaryArn");
    CHECK(arn != NULL &&
              strcmp(arn, "arn:aws:iam::123456789012:policy/"
                          "stackctl-boundary") == 0,
          "PermissionsBoundaryArn passed verbatim");
    config_free(cfg);
}

/* ------------------------------------------------------------------------- */
/* Key lifecycle (core/iam)                                                  */
/* ------------------------------------------------------------------------- */

static int run_keys(fake *f, stackctl_config *cfg, fixture *fx) {
    provision_env env = make_env(f, cfg, fx);
    int mismatch = 0;
    int rc;

    env.ops = &fake_ops;
    env.ops_ud = f;
    rc = provision_ensure_keys(&env, &fake_ops, f, (aws_ctx *)f, &mismatch);
    if (mismatch != 0) {
        return CLI_EXIT_VERIFY;
    }
    return rc;
}

static void test_keys_reuse_enforces_single(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.op_key_count = 1;
    snprintf(f.op_key_ids[0], sizeof(f.op_key_ids[0]), "AKIAOLD");
    f.have_local_op = 1;
    snprintf(f.local_op_key, sizeof(f.local_op_key), "AKIAOLD");
    f.ci_key_count = 1;
    snprintf(f.ci_key_ids[0], sizeof(f.ci_key_ids[0]), "AKIACIOLD");
    f.have_local_ci = 1;
    snprintf(f.local_ci_key, sizeof(f.local_ci_key), "AKIACIOLD");
    CHECK(run_keys(&f, cfg, &fx) == 0, "reuse succeeds");
    CHECK(f.create_count == 0, "no key minted on reuse");
    CHECK(f.write_count == 0, "profile not rewritten on reuse");
    CHECK(f.delete_count == 0, "exactly-one already satisfied");
    CHECK(f.identity_attempts == 1, "operator identity verified on reuse");
    config_free(cfg);
}

static void test_keys_prune_before_create_and_rotate(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.op_key_count = 2;
    snprintf(f.op_key_ids[0], sizeof(f.op_key_ids[0]), "AKIAOLD");
    snprintf(f.op_key_ids[1], sizeof(f.op_key_ids[1]), "AKIAEXTRA");
    f.have_local_op = 1;
    snprintf(f.local_op_key, sizeof(f.local_op_key), "AKIAOLD");
    f.ci_key_count = 1;
    snprintf(f.ci_key_ids[0], sizeof(f.ci_key_ids[0]), "AKIACIOLD");
    f.have_local_ci = 1;
    snprintf(f.local_ci_key, sizeof(f.local_ci_key), "AKIACIOLD");
    f.identity_eacces_attempts = 0;
    {
        provision_env env = make_env(&f, cfg, &fx);
        int mismatch = 0;

        env.rotate = 1;
        CHECK(provision_ensure_keys(&env, &fake_ops, &f, (aws_ctx *)&f,
                                    &mismatch) == 0,
              "rotation succeeds");
    }
    CHECK(f.create_count == 1, "one operator key minted");
    CHECK(f.delete_count == 2, "extra pruned, old deleted after verify");
    CHECK(strcmp(f.deleted_ids[0], "AKIAEXTRA") == 0,
          "extra pruned before create");
    CHECK(strcmp(f.deleted_ids[1], "AKIAOLD") == 0,
          "previous local key deleted last");
    CHECK(trace_index(&f, TRACE_DELETE_KEY) < trace_index(&f, TRACE_CREATE_KEY),
          "prune-before-create");
    CHECK(trace_index(&f, TRACE_CREATE_KEY) < trace_index(&f, TRACE_IDENTITY),
          "identity after create");
    CHECK(f.write_count == 1, "operator profile written");
    CHECK(strcmp(f.written_key, "AKIANEW1") == 0, "new key id written");
    config_free(cfg);
}

static void test_keys_missing_local_mints(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.op_key_count = 1;
    snprintf(f.op_key_ids[0], sizeof(f.op_key_ids[0]), "AKIAOLD");
    f.have_local_op = 0;
    f.ci_key_count = 1;
    snprintf(f.ci_key_ids[0], sizeof(f.ci_key_ids[0]), "AKIACIOLD");
    f.have_local_ci = 1;
    snprintf(f.local_ci_key, sizeof(f.local_ci_key), "AKIACIOLD");
    CHECK(run_keys(&f, cfg, &fx) == 0, "missing local profile mints");
    CHECK(f.create_count == 1, "one operator key minted");
    CHECK(f.delete_count == 1, "unmatched IAM key pruned");
    CHECK(strcmp(f.deleted_ids[0], "AKIAOLD") == 0, "pruned the old id");
    CHECK(f.write_count == 1, "profile written");
    config_free(cfg);
}

static void test_keys_ci_not_auto_minted(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.op_key_count = 1;
    snprintf(f.op_key_ids[0], sizeof(f.op_key_ids[0]), "AKIAOLD");
    f.have_local_op = 1;
    snprintf(f.local_op_key, sizeof(f.local_op_key), "AKIAOLD");
    f.ci_key_count = 1;
    snprintf(f.ci_key_ids[0], sizeof(f.ci_key_ids[0]), "AKIACIOLD");
    f.have_local_ci = 0;
    CHECK(run_keys(&f, cfg, &fx) == 0, "CI key left intact");
    CHECK(f.create_count == 0, "CI key not auto-minted while IAM holds one");
    CHECK(f.delete_count == 0, "CI key not pruned without rotation");
    config_free(cfg);
}

static void test_keys_identity_retries_six(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;

    fixture_init(&fx);
    cfg = load_config(&fx);
    f.ci_key_count = 1;
    snprintf(f.ci_key_ids[0], sizeof(f.ci_key_ids[0]), "AKIACIOLD");
    f.have_local_ci = 1;
    snprintf(f.local_ci_key, sizeof(f.local_ci_key), "AKIACIOLD");
    f.identity_eacces_attempts = 5;
    CHECK(run_keys(&f, cfg, &fx) == 0, "eventual consistency succeeds");
    CHECK(f.identity_attempts == 6, "retried InvalidClientTokenId up to 6");

    fixture_init(&fx);
    cfg = load_config(&fx);
    f = (fake){0};
    f.ci_key_count = 1;
    snprintf(f.ci_key_ids[0], sizeof(f.ci_key_ids[0]), "AKIACIOLD");
    f.have_local_ci = 1;
    snprintf(f.local_ci_key, sizeof(f.local_ci_key), "AKIACIOLD");
    f.identity_eacces_attempts = 100;
    CHECK(run_keys(&f, cfg, &fx) == EACCES, "persistent failure propagates");
    CHECK(f.identity_attempts == 6, "bounded at six attempts");
    config_free(cfg);
}

/* ------------------------------------------------------------------------- */
/* §6.3 operator-template gate                                               */
/* ------------------------------------------------------------------------- */

static void test_operator_template_gate_accepts_canonical(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;

    fixture_init(&fx);
    fixture_install_operator(&fx);
    cfg = load_config(&fx);
    f.read_templates = 1;
    f.stack_present = 0;
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    CHECK(provision_run(&env) == CLI_EXIT_OK,
          "canonical operator template passes the gate");
    CHECK(f.executed == 1, "provision proceeds after a passing gate");
    CHECK(trace_index(&f, TRACE_TEMPLATE) < trace_index(&f, TRACE_AWS_INIT),
          "template gate runs before any AWS call");
    config_free(cfg);
}

static void test_operator_template_gate_rejects_tampered(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    FILE *errors;
    char captured[8192];
    size_t got;
    int saved_stderr;
    int rc;

    fixture_init(&fx);
    fixture_install_tampered_operator(&fx);
    cfg = load_config(&fx);
    f.read_templates = 1;
    f.stack_present = 0;
    f.change_count = 1;
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
    rc = provision_run(&env);
    fflush(stderr);
    if (saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    rewind(errors);
    got = fread(captured, 1, sizeof(captured) - 1, errors);
    captured[got] = '\0';
    fclose(errors);

    CHECK(rc == CLI_EXIT_USAGE, "tampered operator template exits usage (1)");
    CHECK(strstr(captured, "wildcard") != NULL,
          "the violation is named in stderr");
    CHECK(strstr(captured, "stackctl-operator.yaml") != NULL,
          "the template path is named in stderr");
    CHECK(trace_index(&f, TRACE_AWS_INIT) < 0, "no AWS init");
    CHECK(trace_index(&f, TRACE_CREATE_CS) < 0, "no change set");
    CHECK(f.executed == 0, "nothing executed");
    config_free(cfg);
}

static void test_region_variant_derived_from_config(void) {
    fixture fx;
    stackctl_config *primary = NULL;
    stackctl_config *variant = NULL;
    char path[PATH_MAX];
    char variant_env[2048];
    const char *marker;

    fixture_init(&fx);
    CHECK(config_load(fx.config_dir, 0, NULL, &primary) == 0,
          "primary config loads");
    CHECK(provision_region_variant(fx.config_dir, primary) == 0,
          "primary config is not a variant");
    config_free(primary);

    snprintf(path, sizeof(path), "%s/.env.eu-west-1", fx.config_dir);
    marker = strstr(base_env, "REGION=us-east-1");
    CHECK(marker != NULL, "base env has a region");
    if (marker == NULL) {
        return;
    }
    snprintf(variant_env, sizeof(variant_env), "%.*sREGION=eu-west-1%s",
             (int)(marker - base_env), base_env,
             marker + strlen("REGION=us-east-1"));
    write_text(path, variant_env);
    CHECK(config_load(fx.config_dir, 1, "eu-west-1", &variant) == 0,
          "variant config loads");
    CHECK(provision_region_variant(fx.config_dir, variant) == 1,
          "variant derived from config, not file existence");
    config_free(variant);
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
    rc = provision_prod_aws_init_for_test("prod-abort", &aws);
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


/* F20: an interrupted stack wait says the work continues server-side. */
static void test_wait_stack_signal_diagnostic(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    FILE *errors;

    fixture_init(&fx);
    cfg = load_config(&fx);
    errors = tmpfile();
    CHECK(cfg != NULL && errors != NULL, "wait diagnostic fixture opens");
    if (cfg == NULL || errors == NULL) {
        config_free(cfg);
        if (errors != NULL) {
            fclose(errors);
        }
        return;
    }
    f.stack_present = 0;
    f.change_count = 1;
    f.wait_stack_rc = EINTR;
    env = make_env(&f, cfg, &fx);
    env.err = errors;
    CHECK(provision_run(&env) == CLI_EXIT_AWS, "interrupted wait exits 2");
    CHECK(stream_contains(errors, "continues server-side"),
          "interrupted-wait diagnostic says the operation continues");
    CHECK(stream_contains(errors, "stackctl status"),
          "interrupted-wait diagnostic points at stackctl status");
    fclose(errors);
    config_free(cfg);
}

/* Deferred (a): the placeholder CiUserName output is not a real CI user. */
static void test_ci_placeholder_output_no_warning(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    FILE *errors;

    fixture_init(&fx);
    fixture_env_with(&fx, "RELEASE_PREFIXES=releases/", "RELEASE_PREFIXES=");
    cfg = load_config(&fx);
    errors = tmpfile();
    CHECK(cfg != NULL && errors != NULL, "placeholder fixture opens");
    if (cfg == NULL || errors == NULL) {
        config_free(cfg);
        if (errors != NULL) {
            fclose(errors);
        }
        return;
    }
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.ci_output = "-";
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    env.err = errors;
    CHECK(provision_run(&env) == CLI_EXIT_OK,
          "placeholder output run succeeds");
    CHECK(!stream_contains(errors, "deletes CiUser"),
          "placeholder output does not warn about CI-user removal");
    fclose(errors);
    config_free(cfg);
}

static void test_ci_real_output_empty_prefixes_warns(void) {
    fixture fx;
    fake f = {0};
    stackctl_config *cfg;
    provision_env env;
    FILE *errors;

    fixture_init(&fx);
    fixture_env_with(&fx, "RELEASE_PREFIXES=releases/", "RELEASE_PREFIXES=");
    cfg = load_config(&fx);
    errors = tmpfile();
    CHECK(cfg != NULL && errors != NULL, "real-output fixture opens");
    if (cfg == NULL || errors == NULL) {
        config_free(cfg);
        if (errors != NULL) {
            fclose(errors);
        }
        return;
    }
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_UPDATE_COMPLETE;
    f.ci_output = "demo-ci";
    f.change_count = 1;
    env = make_env(&f, cfg, &fx);
    env.err = errors;
    CHECK(provision_run(&env) == CLI_EXIT_OK, "real-output run succeeds");
    CHECK(stream_contains(errors, "deletes CiUser"),
          "real CiUserName output with empty prefixes warns");
    fclose(errors);
    config_free(cfg);
}

int main(void) {
    test_prod_aws_init_installs_abort_hook();
    test_null_context();
    test_region_variant_rejected();
    test_template_failure_is_usage();
    test_in_progress_stack_exits_2();
    test_rollback_complete_exits_2();
    test_create_path_executes_in_order();
    test_update_path_uses_update_change_set();
    test_dry_run_deletes_change_set();
    test_decline_deletes_change_set();
    test_noninteractive_without_yes_is_usage();
    test_empty_change_set_skips_prompt_and_execute();
    test_conforming_stack_still_runs_key_lifecycle();
    test_execute_failure_is_aws();
    test_wait_stack_failure_is_aws();
    test_identity_mismatch_is_verify();
    test_union_of_region_variants();
    test_ci_user_enabled_with_prefixes();
    test_ci_user_disabled_without_prefixes();
    test_ci_user_removal_warns();
    test_wait_stack_signal_diagnostic();
    test_ci_placeholder_output_no_warning();
    test_ci_real_output_empty_prefixes_warns();
    test_cert_bucket_disabled_without_cert_module();
    test_permissions_boundary_passed_when_set();
    test_keys_reuse_enforces_single();
    test_keys_prune_before_create_and_rotate();
    test_keys_missing_local_mints();
    test_keys_ci_not_auto_minted();
    test_keys_identity_retries_six();
    test_operator_template_gate_accepts_canonical();
    test_operator_template_gate_rejects_tampered();
    test_region_variant_derived_from_config();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("provision_test: ok\n");
    return 0;
}
