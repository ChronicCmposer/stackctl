/*
 * stack_test.c — end-to-end tests for the stack-side verbs.
 *
 * Drives provision, deploy and refresh-ami through their internal verb bodies
 * (`provision_run`, `deploy_run`, `refresh_ami_execute`) — the seams the
 * `cli_cmd_*` wrappers call — with injected AWS seams and real temporary
 * config files. Covers the spec §4 acceptance scenarios:
 *   - provision key lifecycle (reuse, rotate prune-before-create, CI keys never
 *     auto-minted, identity guard) and the change-set apply/decline path;
 *   - deploy provenance/freshness failures, publish ordering, rollback of an
 *     existing tag, change-set decline cleanup and prune protections;
 *   - refresh-ami dual-write of .env + .env.example, dry-run and policy errors.
 *
 * No network, no AWS credentials, no git and no bazel are involved.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/cli/provision/provision_internal.h"
#include "core/cli/deploy/deploy_internal.h"
#include "core/cli/refresh_ami/refresh_ami_internal.h"
#include "core/config/config.h"

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

/* ------------------------------------------------------------------------- */
/* Temporary repository fixture                                              */
/* ------------------------------------------------------------------------- */

typedef struct fixture {
    char root[PATH_MAX];
    char config_dir[PATH_MAX];
} fixture;

static void mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t length = strlen(path);

    if (length == 0 || length >= sizeof buffer) {
        exit(1);
    }
    memcpy(buffer, path, length + 1);
    for (char *p = buffer + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(buffer, 0777);
            *p = '/';
        }
    }
    (void)mkdir(buffer, 0777);
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

static char *read_text(const char *path) {
    FILE *file = fopen(path, "rb");
    char *buffer;
    long size;

    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    buffer = calloc((size_t)size + 1, 1);
    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        buffer = NULL;
    }
    fclose(file);
    return buffer;
}

static void fixture_init(fixture *fx, const char *env_body) {
    char template[] = "/tmp/stackctl-stack-XXXXXX";
    char *root = mkdtemp(template);
    char path[PATH_MAX];

    memset(fx, 0, sizeof *fx);
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof fx->root, "%s", root);
    snprintf(fx->config_dir, sizeof fx->config_dir, "%s/deploy/aws", fx->root);
    mkdir_p(fx->config_dir);
    snprintf(path, sizeof path, "%s/MODULE.bazel", fx->root);
    write_text(path, "");
    snprintf(path, sizeof path, "%s/.env", fx->config_dir);
    write_text(path, env_body);
}

/* Remove a temporary tree without invoking host tools (Amendment 4). */
static void remove_tree(const char *path) {
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(path, &st) != 0) {
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path);
        return;
    }
    dir = opendir(path);
    if (dir != NULL) {
        while ((entry = readdir(dir)) != NULL) {
            char child[PATH_MAX];

            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            if (snprintf(child, sizeof child, "%s/%s", path, entry->d_name) >=
                (int)sizeof child) {
                continue;
            }
            remove_tree(child);
        }
        closedir(dir);
    }
    (void)rmdir(path);
}

static void fixture_done(fixture *fx) { remove_tree(fx->root); }

static const char *base_env(void) {
    return "PROJECT=demo\n"
           "REGION=us-east-1\n"
           "ARCH=amd64\n"
           "SPOT_DEFAULT=false\n"
           "AMI_POLICY=pinned\n"
           "AMI_ID_AMD64=ami-old-amd64\n"
           "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"
           "ROOT_VOLUME_SIZE=100\n"
           "KEY_NAME=demo-key\n"
           "SSH_IDENTITY=/home/operator/.ssh/demo\n"
           "BUCKET_MODULES=artifact,cert\n"
           "ENABLE_IMAGE_BUILDER=false\n"
           "SETUP_ENTRYPOINT=deploy.sh\n"
           "SSH_PORT=22\n"
           "SERVICE_UNIT=demo.service\n"
           "OPERATOR_CIDR=203.0.113.0/24\n"
           "INGRESS_TCP=443\n"
           "INGRESS_UDP=\n"
           "RELEASE_TARGETS=//app:deploy.tar.gz\n"
           "RELEASE_PREFIXES=releases/\n";
}

/* ------------------------------------------------------------------------- */
/* Provision fakes                                                           */
/* ------------------------------------------------------------------------- */

enum {
    PT_AWS_INIT = 1,
    PT_CFN_CREATE,
    PT_DESCRIBE,
    PT_CREATE_CS,
    PT_WAIT_CS,
    PT_DESC_CS,
    PT_EXECUTE,
    PT_WAIT_STACK,
    PT_DELETE_CS,
    PT_IDENTITY,
    PT_LIST,
    PT_CREATE_KEY,
    PT_DELETE_KEY,
    PT_CRED_READ,
    PT_WRITE_CRED,
};

typedef struct pfake {
    int trace[64];
    int trace_count;

    int stack_present;
    cfn_stack_status status;
    int create_rc;
    int change_count;
    int execute_rc;
    int wait_cs_rc;
    int wait_stack_rc;
    int delete_cs_rc;
    int delete_stack_rc;

    int identity_mismatch;
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
    char deleted_ids[8][64];
    int write_count;
    char written_key[64];
    char executed;
    int deleted_change_sets;
    int deleted_stacks;
} pfake;

static void ptrace(pfake *f, int tag) {
    if (f->trace_count < (int)ARRAY_LEN(f->trace)) {
        f->trace[f->trace_count++] = tag;
    }
}

static int ptrace_index(const pfake *f, int tag) {
    for (int i = 0; i < f->trace_count; i++) {
        if (f->trace[i] == tag) {
            return i;
        }
    }
    return -1;
}

static int p_aws_init(void *ud, const char *profile, aws_ctx **out) {
    pfake *f = ud;

    (void)profile;
    ptrace(f, PT_AWS_INIT);
    *out = (aws_ctx *)f;
    return 0;
}

static void p_aws_free(void *ud, aws_ctx *aws) {
    (void)ud;
    (void)aws;
}

static int p_cfn_create(void *ud, aws_ctx *aws, cfn_client **out) {
    pfake *f = ud;

    (void)aws;
    ptrace(f, PT_CFN_CREATE);
    *out = (cfn_client *)f;
    return 0;
}

static void p_cfn_destroy(void *ud, cfn_client *client) {
    (void)ud;
    (void)client;
}

static int p_describe(void *ud, cfn_client *client, const char *region,
                      const char *name, cfn_stack_list *out) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)name;
    ptrace(f, PT_DESCRIBE);
    if (!f->stack_present) {
        return ENOENT;
    }
    out->items = calloc(1, sizeof *out->items);
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    out->items[0].status = f->status;
    return 0;
}

static void p_stack_list_free(void *ud, cfn_stack_list *list) {
    (void)ud;
    if (list != NULL) {
        free(list->items);
        list->items = NULL;
        list->count = 0;
    }
}

static int p_create_cs(void *ud, cfn_client *client, const char *region,
                       const cfn_change_set_spec *spec,
                       cfn_change_set_result *out) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)spec;
    ptrace(f, PT_CREATE_CS);
    snprintf(out->change_set_id, sizeof out->change_set_id, "%s", "cs-1");
    return f->create_rc;
}

static int p_wait_cs(void *ud, cfn_client *client, const char *region,
                     const char *stack, const char *cs, int attempts,
                     int interval, int *timed_out, int *no_changes) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    (void)attempts;
    (void)interval;
    ptrace(f, PT_WAIT_CS);
    if (timed_out != NULL) {
        *timed_out = 0;
    }
    if (no_changes != NULL) {
        *no_changes = 0;
    }
    return f->wait_cs_rc;
}

static int p_desc_cs(void *ud, cfn_client *client, const char *region,
                     const char *stack, const char *cs,
                     cfn_change_set *out) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    ptrace(f, PT_DESC_CS);
    out->change_count = (size_t)f->change_count;
    out->execution_status = CFN_CHANGE_SET_EXECUTION_AVAILABLE;
    return 0;
}

static void p_change_set_free(void *ud, cfn_change_set *cs) {
    (void)ud;
    (void)cs;
}

static int p_execute(void *ud, cfn_client *client, const char *region,
                     const char *stack, const char *cs) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    ptrace(f, PT_EXECUTE);
    f->executed = 1;
    return f->execute_rc;
}

static int p_delete_cs(void *ud, cfn_client *client, const char *region,
                       const char *stack, const char *cs) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    ptrace(f, PT_DELETE_CS);
    f->deleted_change_sets++;
    return f->delete_cs_rc;
}

static int p_wait_stack(void *ud, cfn_client *client, const char *region,
                        const char *stack, cfn_wait_operation op, int attempts,
                        int interval, int *timed_out) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)op;
    (void)attempts;
    (void)interval;
    ptrace(f, PT_WAIT_STACK);
    if (timed_out != NULL) {
        *timed_out = 0;
    }
    return f->wait_stack_rc;
}

static int p_delete_stack(void *ud, cfn_client *client, const char *region,
                          const char *stack) {
    pfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    f->deleted_stacks++;
    return f->delete_stack_rc;
}

static int p_identity(void *ud, aws_ctx *ctx, char **out_arn) {
    pfake *f = ud;

    (void)ctx;
    ptrace(f, PT_IDENTITY);
    *out_arn = strdup(f->identity_mismatch
                          ? "arn:aws:iam::123456789012:user/other"
                          : "arn:aws:iam::123456789012:user/demo");
    return *out_arn != NULL ? 0 : ENOMEM;
}

static int p_list_keys(void *ud, aws_ctx *ctx, const char *user,
                       iam_key **out, size_t *out_count) {
    pfake *f = ud;
    int is_ci = user != NULL && strstr(user, "-ci") != NULL;
    int count = is_ci ? f->ci_key_count : f->op_key_count;

    (void)ctx;
    ptrace(f, PT_LIST);
    *out = NULL;
    *out_count = 0;
    if (count == 0) {
        return 0;
    }
    *out = calloc((size_t)count, sizeof **out);
    if (*out == NULL) {
        return ENOMEM;
    }
    for (int i = 0; i < count; i++) {
        (*out)[i].user_name = strdup(is_ci ? "demo-ci" : "demo");
        (*out)[i].access_key_id =
            strdup(is_ci ? f->ci_key_ids[i] : f->op_key_ids[i]);
        (*out)[i].status = strdup("Active");
    }
    *out_count = (size_t)count;
    return 0;
}

static int p_create_key(void *ud, aws_ctx *ctx, const char *user,
                        iam_key *out) {
    pfake *f = ud;
    char id[64];

    (void)ctx;
    ptrace(f, PT_CREATE_KEY);
    f->create_count++;
    snprintf(id, sizeof id, "AKIANEW%d", f->create_count);
    out->user_name = strdup(user != NULL ? user : "demo");
    out->access_key_id = strdup(id);
    out->secret_access_key = strdup("SECRETNEW");
    out->status = strdup("Active");
    return 0;
}

static int p_delete_key(void *ud, aws_ctx *ctx, const char *user,
                        const char *key_id) {
    pfake *f = ud;

    (void)ctx;
    (void)user;
    ptrace(f, PT_DELETE_KEY);
    if (f->delete_count < (int)ARRAY_LEN(f->deleted_ids)) {
        snprintf(f->deleted_ids[f->delete_count],
                 sizeof f->deleted_ids[0], "%s", key_id);
    }
    f->delete_count++;
    return 0;
}

static void p_key_free(void *ud, iam_key *key) {
    (void)ud;
    free(key->user_name);
    free(key->access_key_id);
    free(key->secret_access_key);
    free(key->status);
    free(key->create_date);
    memset(key, 0, sizeof *key);
}

static void p_keys_free(void *ud, iam_key *keys, size_t count) {
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

static int p_cred_read(void *ud, const char *profile, char **out) {
    pfake *f = ud;
    int is_ci = strstr(profile, "-ci") != NULL;

    ptrace(f, PT_CRED_READ);
    *out = NULL;
    if (is_ci && f->have_local_ci) {
        *out = strdup(f->local_ci_key);
    } else if (!is_ci && f->have_local_op) {
        *out = strdup(f->local_op_key);
    }
    return 0;
}

static int p_cred_write(void *ud, const char *profile, const char *key_id,
                        const char *secret, char **backup_out) {
    pfake *f = ud;

    (void)secret;
    ptrace(f, PT_WRITE_CRED);
    f->write_count++;
    snprintf(f->written_key, sizeof f->written_key, "%s", key_id);
    (void)profile;
    if (backup_out != NULL) {
        *backup_out = NULL;
    }
    return 0;
}

static void p_retry_pause(void *ud, int attempt) {
    (void)ud;
    (void)attempt;
}

static int p_template(void *ud, const char *repo_root, char **body_out) {
    (void)ud;
    (void)repo_root;
    *body_out = strdup("Resources: {}\n");
    return *body_out != NULL ? 0 : ENOMEM;
}

static const provision_ops P_OPS = {
    .aws_init = p_aws_init,
    .aws_free = p_aws_free,
    .cfn_create = p_cfn_create,
    .cfn_destroy = p_cfn_destroy,
    .describe_stacks = p_describe,
    .stack_list_free = p_stack_list_free,
    .create_change_set = p_create_cs,
    .wait_change_set = p_wait_cs,
    .describe_change_set = p_desc_cs,
    .change_set_free = p_change_set_free,
    .execute_change_set = p_execute,
    .delete_change_set = p_delete_cs,
    .wait_stack = p_wait_stack,
    .delete_stack = p_delete_stack,
    .iam_identity = p_identity,
    .iam_list_keys = p_list_keys,
    .iam_create_key = p_create_key,
    .iam_delete_key = p_delete_key,
    .iam_key_free = p_key_free,
    .iam_keys_free = p_keys_free,
    .credentials_key_id = p_cred_read,
    .credentials_write = p_cred_write,
    .retry_pause = p_retry_pause,
    .read_template = p_template,
};

static int confirm_yes(void *ud, const char *prompt) {
    int *result = ud;

    (void)prompt;
    return *result;
}

static void provision_base(pfake *f) {
    memset(f, 0, sizeof *f);
    f->stack_present = 0;
    f->change_count = 1;
    f->op_key_count = 1;
    snprintf(f->op_key_ids[0], sizeof f->op_key_ids[0], "%s", "AKIAOLD");
    f->have_local_op = 1;
    snprintf(f->local_op_key, sizeof f->local_op_key, "%s", "AKIAOLD");
    /* The CI user is in scope (RELEASE_PREFIXES present): give it one key
     * both in IAM and locally so the baseline mints nothing. */
    f->ci_key_count = 1;
    snprintf(f->ci_key_ids[0], sizeof f->ci_key_ids[0], "%s", "AKIACI");
    f->have_local_ci = 1;
    snprintf(f->local_ci_key, sizeof f->local_ci_key, "%s", "AKIACI");
}

static int run_provision(const fixture *fx, pfake *f, int rotate,
                         int rotate_ci) {
    stackctl_config *cfg = NULL;
    provision_env env;
    int confirm = CLI_CONFIRM_YES;

    if (config_load(fx->config_dir, 0, NULL, &cfg) != 0) {
        return -1;
    }
    memset(&env, 0, sizeof env);
    env.cfg = cfg;
    env.config_dir = fx->config_dir;
    env.region_variant = 0;
    env.yes = 1;
    env.rotate = rotate;
    env.rotate_ci = rotate_ci;
    env.out = stdout;
    env.err = stderr;
    env.ops = &P_OPS;
    env.ops_ud = f;
    env.confirm = confirm_yes;
    env.confirm_ud = &confirm;
    int rc = provision_run(&env);
    config_free(cfg);
    return rc;
}

static void scenario_provision_keys(fixture *fx) {
    pfake f;

    /* Re-run reuses the existing local key: no mint, no delete, no write. */
    provision_base(&f);
    CHECK(run_provision(fx, &f, 0, 0) == CLI_EXIT_OK, "provision re-run ok");
    CHECK(f.create_count == 0, "existing key reused (no mint)");
    CHECK(f.delete_count == 0, "existing key not deleted");
    CHECK(f.write_count == 0, "profile rewritten only when needed");
    CHECK(f.executed == 1, "operator stack change set executed");
    CHECK(ptrace_index(&f, PT_DESCRIBE) < ptrace_index(&f, PT_CREATE_CS) &&
              ptrace_index(&f, PT_CREATE_CS) < ptrace_index(&f, PT_EXECUTE) &&
              ptrace_index(&f, PT_EXECUTE) < ptrace_index(&f, PT_WAIT_STACK),
          "describe -> change set -> execute -> wait ordering");

    /* --rotate: prune-before-create then write exactly the new key. */
    provision_base(&f);
    CHECK(run_provision(fx, &f, 1, 0) == CLI_EXIT_OK, "rotate ok");
    CHECK(f.create_count == 1, "rotation mints one key");
    CHECK(f.delete_count == 1, "rotation deletes the previous key");
    CHECK(strcmp(f.deleted_ids[0], "AKIAOLD") == 0, "previous key deleted");
    CHECK(strcmp(f.written_key, "AKIANEW1") == 0, "new key written");
    CHECK(f.write_count == 1, "credentials written once");

    /* CI key exists in IAM but not locally: never auto-minted. */
    provision_base(&f);
    f.have_local_ci = 0; /* key lives only in CI secrets */
    CHECK(run_provision(fx, &f, 0, 0) == CLI_EXIT_OK, "CI with keys ok");
    CHECK(f.create_count == 0, "CI key not auto-minted while IAM holds one");

    /* Identity guard mismatch is exit 3. */
    provision_base(&f);
    f.identity_mismatch = 1;
    CHECK(run_provision(fx, &f, 0, 0) == CLI_EXIT_VERIFY,
          "identity mismatch exit 3");
}

/* ------------------------------------------------------------------------- */
/* Deploy fakes                                                              */
/* ------------------------------------------------------------------------- */

enum {
    DT_PROVENANCE = 1,
    DT_FRESHNESS,
    DT_BUCKET,
    DT_AMI,
    DT_AMI_EXISTS,
    DT_REL_EXISTS,
    DT_VERIFY,
    DT_PUBLISH,
    DT_DESCRIBE,
    DT_CREATE_CS,
    DT_WAIT_CS,
    DT_DESC_CS,
    DT_EXECUTE,
    DT_WAIT_STACK,
    DT_DELETE_CS,
    DT_LIVE,
    DT_PRUNE,
};

typedef struct dfake {
    int trace[64];
    int trace_count;

    int provenance_rc;
    char provenance_tag[64];
    int freshness_rc;
    int rel_exists;
    int rel_exists_rc;
    int verify_rc;
    char verify_sha[65];
    int publish_rc;
    int prune_rc;

    int stack_present;
    cfn_stack_status status;
    int change_count;
    int execute_rc;
    int wait_cs_rc;
    int wait_stack_rc;
    int delete_cs_rc;

    int executed;
    int deleted_change_sets;
    int publish_count;
    int verify_count;
    int prune_calls;
    char prune_pinned[128];
    char prune_previous[128];
    char prune_uploaded[128];
} dfake;

static void dtrace(dfake *f, int tag) {
    if (f->trace_count < (int)ARRAY_LEN(f->trace)) {
        f->trace[f->trace_count++] = tag;
    }
}

static int dtrace_index(const dfake *f, int tag) {
    for (int i = 0; i < f->trace_count; i++) {
        if (f->trace[i] == tag) {
            return i;
        }
    }
    return -1;
}

static int dtrace_nth_index(const dfake *f, int tag, int nth) {
    for (int i = 0; i < f->trace_count; i++) {
        if (f->trace[i] == tag && --nth == 0) {
            return i;
        }
    }
    return -1;
}

static int d_aws_init(void *ud, const char *profile, aws_ctx **out) {
    (void)profile;
    *out = (aws_ctx *)ud;
    return 0;
}

static void d_aws_free(void *ud, aws_ctx *aws) {
    (void)ud;
    (void)aws;
}

static int d_cfn_create(void *ud, aws_ctx *aws, cfn_client **out) {
    (void)aws;
    *out = (cfn_client *)ud;
    return 0;
}

static void d_cfn_destroy(void *ud, cfn_client *client) {
    (void)ud;
    (void)client;
}

static int d_provenance(void *ud, const char *repo_root, int allow_dirty,
                        char *tag, size_t cap) {
    dfake *f = ud;

    (void)repo_root;
    (void)allow_dirty;
    dtrace(f, DT_PROVENANCE);
    if (f->provenance_rc != 0) {
        return f->provenance_rc;
    }
    snprintf(tag, cap, "%s", f->provenance_tag);
    return 0;
}

static int d_freshness(void *ud, const char *repo_root, const char *targets) {
    dfake *f = ud;

    (void)repo_root;
    (void)targets;
    dtrace(f, DT_FRESHNESS);
    return f->freshness_rc;
}

static int d_bucket(void *ud, const char *project, const char *region,
                    char *out, size_t cap) {
    dfake *f = ud;

    (void)project;
    (void)region;
    dtrace(f, DT_BUCKET);
    snprintf(out, cap, "%s", "demo-artifacts-123-us-east-1");
    return 0;
}

static int d_resolve_ami(void *ud, const stackctl_config *cfg,
                         const char *region, const char *arch, char *out,
                         size_t cap) {
    dfake *f = ud;

    (void)cfg;
    (void)region;
    (void)arch;
    dtrace(f, DT_AMI);
    snprintf(out, cap, "%s", "ami-ok");
    return 0;
}

static int d_ami_exists(void *ud, const char *region, const char *ami,
                        int *found) {
    dfake *f = ud;

    (void)region;
    (void)ami;
    dtrace(f, DT_AMI_EXISTS);
    *found = 1;
    return 0;
}

static int d_release_exists(void *ud, const char *bucket, const char *tag,
                            int *exists) {
    dfake *f = ud;

    (void)bucket;
    (void)tag;
    dtrace(f, DT_REL_EXISTS);
    if (f->rel_exists_rc != 0) {
        return f->rel_exists_rc;
    }
    *exists = f->rel_exists;
    return 0;
}

static int d_verify(void *ud, const char *bucket, const char *tag,
                    char *sha_out, size_t cap) {
    dfake *f = ud;

    (void)bucket;
    (void)tag;
    dtrace(f, DT_VERIFY);
    f->verify_count++;
    if (f->verify_rc != 0) {
        return f->verify_rc;
    }
    snprintf(sha_out, cap, "%s", f->verify_sha);
    return 0;
}

static int d_publish(void *ud, const char *bucket, const char *tag,
                     const char *repo_root, const char *targets,
                     char *sha_out, size_t cap) {
    dfake *f = ud;

    (void)bucket;
    (void)tag;
    (void)repo_root;
    (void)targets;
    dtrace(f, DT_PUBLISH);
    f->publish_count++;
    if (f->publish_rc != 0) {
        return f->publish_rc;
    }
    snprintf(sha_out, cap,
             "%s",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    return 0;
}

static int d_describe(void *ud, cfn_client *client, const char *region,
                      const char *name, cfn_stack_list *out) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)name;
    dtrace(f, DT_DESCRIBE);
    if (!f->stack_present) {
        return ENOENT;
    }
    out->items = calloc(1, sizeof *out->items);
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    out->items[0].status = f->status;
    return 0;
}

static void d_stack_list_free(void *ud, cfn_stack_list *list) {
    (void)ud;
    if (list != NULL) {
        free(list->items);
        list->items = NULL;
        list->count = 0;
    }
}

static int d_create_cs(void *ud, cfn_client *client, const char *region,
                       const cfn_change_set_spec *spec,
                       cfn_change_set_result *out) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)spec;
    dtrace(f, DT_CREATE_CS);
    snprintf(out->change_set_id, sizeof out->change_set_id, "%s", "cs-1");
    return 0;
}

static int d_wait_cs(void *ud, cfn_client *client, const char *region,
                     const char *stack, const char *cs, int attempts,
                     int interval, int *timed_out, int *no_changes) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    (void)attempts;
    (void)interval;
    dtrace(f, DT_WAIT_CS);
    if (timed_out != NULL) {
        *timed_out = 0;
    }
    if (no_changes != NULL) {
        *no_changes = 0;
    }
    return f->wait_cs_rc;
}

static int d_desc_cs(void *ud, cfn_client *client, const char *region,
                     const char *stack, const char *cs,
                     cfn_change_set *out) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    dtrace(f, DT_DESC_CS);
    out->change_count = (size_t)f->change_count;
    out->execution_status = CFN_CHANGE_SET_EXECUTION_AVAILABLE;
    return 0;
}

static void d_change_set_free(void *ud, cfn_change_set *cs) {
    (void)ud;
    (void)cs;
}

static int d_execute(void *ud, cfn_client *client, const char *region,
                     const char *stack, const char *cs) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    dtrace(f, DT_EXECUTE);
    f->executed = 1;
    return f->execute_rc;
}

static int d_delete_cs(void *ud, cfn_client *client, const char *region,
                       const char *stack, const char *cs) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)cs;
    dtrace(f, DT_DELETE_CS);
    f->deleted_change_sets++;
    return f->delete_cs_rc;
}

static int d_wait_stack(void *ud, cfn_client *client, const char *region,
                        const char *stack, cfn_wait_operation op, int attempts,
                        int interval, int *timed_out) {
    dfake *f = ud;

    (void)client;
    (void)region;
    (void)stack;
    (void)op;
    (void)attempts;
    (void)interval;
    dtrace(f, DT_WAIT_STACK);
    if (timed_out != NULL) {
        *timed_out = 0;
    }
    return f->wait_stack_rc;
}

static int d_delete_stack(void *ud, cfn_client *client, const char *region,
                          const char *stack) {
    (void)ud;
    (void)client;
    (void)region;
    (void)stack;
    return 0;
}

static int d_live(void *ud, const char *region, int *count) {
    dfake *f = ud;

    (void)region;
    dtrace(f, DT_LIVE);
    *count = 0;
    return 0;
}

static int d_prune(void *ud, const char *bucket, const char *pinned,
                   const char *previous, const char *uploaded) {
    dfake *f = ud;

    (void)bucket;
    dtrace(f, DT_PRUNE);
    f->prune_calls++;
    snprintf(f->prune_pinned, sizeof f->prune_pinned, "%s",
             pinned != NULL ? pinned : "");
    snprintf(f->prune_previous, sizeof f->prune_previous, "%s",
             previous != NULL ? previous : "");
    snprintf(f->prune_uploaded, sizeof f->prune_uploaded, "%s",
             uploaded != NULL ? uploaded : "");
    return f->prune_rc;
}

static int d_read_template(void *ud, const char *repo_root, char **out) {
    (void)ud;
    (void)repo_root;
    *out = strdup("Resources: {}\n");
    return *out != NULL ? 0 : ENOMEM;
}

static const deploy_ops D_OPS = {
    .aws_init = d_aws_init,
    .aws_free = d_aws_free,
    .cfn_create = d_cfn_create,
    .cfn_destroy = d_cfn_destroy,
    .git_provenance = d_provenance,
    .freshness = d_freshness,
    .resolve_bucket = d_bucket,
    .resolve_ami = d_resolve_ami,
    .ami_exists = d_ami_exists,
    .release_exists = d_release_exists,
    .verify_release = d_verify,
    .publish_release = d_publish,
    .count_live_instances = d_live,
    .prune_releases = d_prune,
    .describe_stacks = d_describe,
    .stack_list_free = d_stack_list_free,
    .create_change_set = d_create_cs,
    .wait_change_set = d_wait_cs,
    .describe_change_set = d_desc_cs,
    .change_set_free = d_change_set_free,
    .execute_change_set = d_execute,
    .delete_change_set = d_delete_cs,
    .wait_stack = d_wait_stack,
    .delete_stack = d_delete_stack,
    .read_template = d_read_template,
};

static int run_deploy(const fixture *fx, dfake *f, const char *tag_arg,
                      int skip_build, int confirm_result) {
    stackctl_config *cfg = NULL;
    deploy_env env;
    int confirm = confirm_result;

    if (config_load(fx->config_dir, 0, NULL, &cfg) != 0) {
        return -1;
    }
    memset(&env, 0, sizeof env);
    env.cfg = cfg;
    env.config_dir = fx->config_dir;
    env.tag_arg = tag_arg;
    env.skip_build = skip_build;
    env.yes = 1;
    env.out = stdout;
    env.err = stderr;
    env.ops = &D_OPS;
    env.ops_ud = f;
    env.confirm = confirm_yes;
    env.confirm_ud = &confirm;
    int rc = deploy_run(&env);
    config_free(cfg);
    return rc;
}

static void deploy_base(dfake *f) {
    memset(f, 0, sizeof *f);
    f->stack_present = 0;
    f->change_count = 1;
    snprintf(f->provenance_tag, sizeof f->provenance_tag, "%s", "v1.2.3");
    snprintf(f->verify_sha, sizeof f->verify_sha,
             "%s",
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}

static void scenario_deploy(fixture *fx) {
    dfake f;

    /* Happy path: provenance -> freshness -> release -> publish -> CFN ->
     * prune, in that order. */
    deploy_base(&f);
    CHECK(run_deploy(fx, &f, NULL, 0, CLI_CONFIRM_YES) == CLI_EXIT_OK,
          "deploy succeeds");
    CHECK(f.publish_count == 1, "new release published");
    CHECK(f.executed == 1, "infra stack updated");
    CHECK(f.prune_calls == 1, "old releases pruned");
    CHECK(strcmp(f.prune_uploaded, "v1.2.3") == 0,
          "just-uploaded tag protected from prune");
    CHECK(dtrace_index(&f, DT_PROVENANCE) < dtrace_index(&f, DT_FRESHNESS) &&
              dtrace_index(&f, DT_FRESHNESS) < dtrace_index(&f, DT_REL_EXISTS) &&
              dtrace_nth_index(&f, DT_CREATE_CS, 1) <
                  dtrace_nth_index(&f, DT_EXECUTE, 1) &&
              dtrace_nth_index(&f, DT_EXECUTE, 1) <
                  dtrace_nth_index(&f, DT_WAIT_STACK, 1) &&
              dtrace_nth_index(&f, DT_WAIT_STACK, 1) <
                  dtrace_index(&f, DT_PUBLISH) &&
              dtrace_index(&f, DT_PUBLISH) <
                  dtrace_nth_index(&f, DT_CREATE_CS, 2) &&
              dtrace_nth_index(&f, DT_CREATE_CS, 2) <
                  dtrace_nth_index(&f, DT_EXECUTE, 2) &&
              dtrace_nth_index(&f, DT_EXECUTE, 2) < dtrace_index(&f, DT_PRUNE),
          "bootstrap-before-publish-before-record-before-prune ordering");

    /* Provenance failure is exit 3 and publishes nothing. */
    deploy_base(&f);
    f.provenance_rc = CLI_EXIT_VERIFY;
    CHECK(run_deploy(fx, &f, NULL, 0, CLI_CONFIRM_YES) == CLI_EXIT_VERIFY,
          "provenance failure exit 3");
    CHECK(f.publish_count == 0, "no publish after provenance failure");

    /* Freshness failure is exit 6 and publishes nothing. */
    deploy_base(&f);
    f.freshness_rc = CLI_EXIT_FRESHNESS;
    CHECK(run_deploy(fx, &f, NULL, 0, CLI_CONFIRM_YES) == CLI_EXIT_FRESHNESS,
          "freshness failure exit 6");
    CHECK(f.publish_count == 0, "no publish after freshness failure");

    /* Rollback: an existing complete tag verifies and is recorded, with no
     * provenance/freshness/publish. */
    deploy_base(&f);
    f.rel_exists = 1;
    f.stack_present = 1;
    f.status = CFN_STACK_STATUS_CREATE_COMPLETE;
    CHECK(run_deploy(fx, &f, "v1.1.0", 0, CLI_CONFIRM_YES) == CLI_EXIT_OK,
          "rollback succeeds");
    CHECK(f.publish_count == 0, "rollback never publishes");
    CHECK(f.verify_count == 1, "rollback verifies the existing manifest");
    CHECK(f.executed == 1, "rollback records the tag on the stack");
    CHECK(dtrace_index(&f, DT_PROVENANCE) < 0, "rollback skips provenance");
    CHECK(dtrace_index(&f, DT_FRESHNESS) < 0, "rollback skips freshness");

    /* Decline: the change set is deleted and the stack is not executed. */
    deploy_base(&f);
    CHECK(run_deploy(fx, &f, NULL, 0, CLI_CONFIRM_NO) == CLI_EXIT_OK,
          "declined deploy is not an error");
    CHECK(f.executed == 0, "declined change set is not executed");
    CHECK(f.deleted_change_sets >= 1, "declined change set is deleted");
    CHECK(f.publish_count == 0,
          "declining the bootstrap change set publishes nothing");
}

static void scenario_prune(void) {
    deploy_release_entry entries[14];
    long long now = 1000000;

    memset(entries, 0, sizeof entries);
    for (size_t i = 0; i < ARRAY_LEN(entries); i++) {
        snprintf(entries[i].tag, sizeof entries[i].tag, "v1.0.%zu", i);
        entries[i].manifest_epoch = now - (long long)(ARRAY_LEN(entries) - i);
        entries[i].newest_epoch = entries[i].manifest_epoch;
    }
    /* Two manifest-less garbage prefixes: one old enough, one in flight. */
    snprintf(entries[0].tag, sizeof entries[0].tag, "v9.9.9");
    entries[0].manifest_epoch = 0;
    entries[0].newest_epoch = now - 25 * 3600;
    snprintf(entries[1].tag, sizeof entries[1].tag, "v9.9.8");
    entries[1].manifest_epoch = 0;
    entries[1].newest_epoch = now - 3600;

    size_t marked = deploy_prune_mark(entries, ARRAY_LEN(entries), "v1.0.13",
                                      "v1.0.12", "v1.0.11", now);
    CHECK(marked == 3, "prune keeps 10 newest + protections, drops old garbage");
    CHECK(entries[0].delete_me == 1, "manifest-less garbage >24h deleted");
    CHECK(entries[1].delete_me == 0, "in-flight garbage kept");
    CHECK(entries[11].delete_me == 0, "just-uploaded tag protected");
    CHECK(entries[12].delete_me == 0, "previous rollback tag protected");
    CHECK(entries[13].delete_me == 0, "stack-pinned tag protected");

    {
        char line[256];

        CHECK(deploy_manifest_line(
                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                  "app.tar", line, sizeof line) == 0,
              "manifest line formats");
        CHECK(strcmp(line,
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                     "aaaa  app.tar\n") == 0,
              "manifest line is sha256sum-compatible (two spaces)");
    }
}

/* ------------------------------------------------------------------------- */
/* refresh-ami                                                               */
/* ------------------------------------------------------------------------- */

static int r_resolve(void *ud, const char *profile, const char *region,
                     const char *name, char **value_out) {
    int *calls = ud;

    (void)profile;
    (void)region;
    (*calls)++;
    if (strstr(name, "amd64") != NULL) {
        *value_out = strdup("ami-new-amd64");
    } else if (strstr(name, "arm64") != NULL) {
        *value_out = strdup("ami-new-arm64");
    } else {
        return ENOENT;
    }
    return *value_out != NULL ? 0 : ENOMEM;
}

static const refresh_ami_ops R_OPS = {.resolve_parameter = r_resolve};

static int run_refresh(const fixture *fx, stackctl_config *cfg, int dry_run) {
    refresh_ami_env env;
    int calls = 0;

    memset(&env, 0, sizeof env);
    env.cfg = cfg;
    env.profile = "demo";
    env.config_dir = fx->config_dir;
    env.region = "us-east-1";
    env.dry_run = dry_run;
    env.out = stdout;
    env.err = stderr;
    env.ops = &R_OPS;
    env.ops_ud = &calls;
    return refresh_ami_run(&env);
}

static void scenario_refresh_ami(void) {
    fixture fx;
    stackctl_config *cfg = NULL;
    char path[PATH_MAX];
    char *body;

    fixture_init(&fx,
                 "PROJECT=demo\n"
                 "REGION=us-east-1\n"
                 "ARCH=both\n"
                 "SPOT_DEFAULT=false\n"
                 "AMI_POLICY=pinned\n"
                 "AMI_ID_AMD64=ami-old-amd64\n"
                 "AMI_ID_ARM64=ami-old-arm64\n"
                 "AMI_SSM_AMD64=/demo/ami/amd64\n"
                 "AMI_SSM_ARM64=/demo/ami/arm64\n"
                 "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"
                 "INSTANCE_TYPES_ARM64=g5g.xlarge\n"
                 "ROOT_VOLUME_SIZE=100\n"
                 "KEY_NAME=demo-key\n"
                 "SSH_IDENTITY=/home/operator/.ssh/demo\n"
                 "BUCKET_MODULES=artifact\n"
                 "ENABLE_IMAGE_BUILDER=false\n"
                 "SETUP_ENTRYPOINT=deploy.sh\n"
                 "SSH_PORT=22\n"
                 "SERVICE_UNIT=demo.service\n"
                 "OPERATOR_CIDR=203.0.113.0/24\n"
                 "INGRESS_TCP=443\n"
                 "INGRESS_UDP=\n"
                 "RELEASE_TARGETS=//app:deploy.tar.gz\n"
                 "RELEASE_PREFIXES=releases/\n");
    snprintf(path, sizeof path, "%s/.env.example", fx.config_dir);
    write_text(path,
               "# example config\n"
               "AMI_ID_AMD64=ami-old-amd64\n"
               "AMI_ID_ARM64=ami-old-arm64\n"
               "PROJECT=demo\n");

    CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == 0, "refresh config loads");
    if (cfg != NULL) {
        /* Dry-run writes nothing. */
        CHECK(run_refresh(&fx, cfg, 1) == CLI_EXIT_OK, "refresh dry-run ok");
        body = read_text(path);
        CHECK(body != NULL && strstr(body, "ami-old-amd64") != NULL,
              "dry-run leaves the example unchanged");
        free(body);

        CHECK(run_refresh(&fx, cfg, 0) == CLI_EXIT_OK, "refresh applies");
        body = read_text(path);
        CHECK(body != NULL && strstr(body, "ami-new-amd64") != NULL,
              "example pin updated");
        CHECK(body != NULL && strstr(body, "ami-new-arm64") != NULL,
              "example arm64 pin updated");
        CHECK(body != NULL && strstr(body, "# example config") != NULL,
              "comments preserved");
        free(body);

        snprintf(path, sizeof path, "%s/.env", fx.config_dir);
        body = read_text(path);
        CHECK(body != NULL && strstr(body, "AMI_ID_AMD64=ami-new-amd64") != NULL,
              "local pin updated");
        CHECK(body != NULL && strstr(body, "PROJECT=demo") != NULL,
              "unrelated keys preserved");
        free(body);

        config_free(cfg);
    }

    /* Under ssm policy refresh-ami is a hard error, never a silent no-op. */
    {
        char text[4096];

        snprintf(text, sizeof text,
                 "PROJECT=demo\nREGION=us-east-1\nARCH=amd64\n"
                 "SPOT_DEFAULT=false\nAMI_POLICY=ssm\n"
                 "AMI_SSM_AMD64=/demo/ami/amd64\n"
                 "INSTANCE_TYPES_AMD64=g4dn.xlarge\nROOT_VOLUME_SIZE=100\n"
                 "KEY_NAME=demo-key\nSSH_IDENTITY=/home/operator/.ssh/demo\n"
                 "BUCKET_MODULES=artifact\nENABLE_IMAGE_BUILDER=false\n"
                 "SETUP_ENTRYPOINT=deploy.sh\nSSH_PORT=22\n"
                 "SERVICE_UNIT=demo.service\nOPERATOR_CIDR=\n"
                 "INGRESS_TCP=443\nINGRESS_UDP=\n"
                 "RELEASE_TARGETS=//a\nRELEASE_PREFIXES=releases/\n");
        snprintf(path, sizeof path, "%s/.env", fx.config_dir);
        write_text(path, text);
        cfg = NULL;
        CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == 0, "ssm config loads");
        if (cfg != NULL) {
            CHECK(run_refresh(&fx, cfg, 0) == CLI_EXIT_USAGE,
                  "ssm policy refuses refresh-ami");
            config_free(cfg);
        }
    }

    fixture_done(&fx);
}

int main(void) {
    fixture fx;
    char xdg[PATH_MAX];

    fixture_init(&fx, base_env());
    snprintf(xdg, sizeof xdg, "%s/state", fx.root);
    mkdir_p(xdg);
    if (setenv("XDG_STATE_HOME", xdg, 1) != 0) {
        perror("setenv");
        return 1;
    }

    scenario_provision_keys(&fx);
    scenario_deploy(&fx);
    scenario_prune();
    fixture_done(&fx);

    scenario_refresh_ami();

    if (failures != 0) {
        fprintf(stderr, "%d stack test(s) failed\n", failures);
        return 1;
    }
    printf("stack_test: ok\n");
    return 0;
}
