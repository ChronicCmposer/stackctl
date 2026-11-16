/*
 * provision.c — `stackctl provision` (spec §4 provision).
 *
 * Deploys the account-global `<project>-operator` stack from the primary
 * config, using a create-or-update change set with a reviewable preview and a
 * confirmation prompt. The operator parameters are the union of every region
 * variant's operator-feeding keys, so one operator stack serves all regions.
 *
 * Stack-state handling never auto-deletes or auto-recovers: in-progress,
 * failed-create (ROLLBACK_COMPLETE), failed-update-rollback and DELETE_FAILED
 * states are AWS-class failures with recovery guidance in the diagnostic.
 */

#include "provision_internal.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aws.h"
#include "core/config/envfile.h"
#include "core/ini/ini.h"
#include "iam.h"
#include "template_check.h"
#include "yyjson.h"

/* ------------------------------------------------------------------------- */
/* Test seam                                                                 */
/* ------------------------------------------------------------------------- */

static const provision_ops *test_ops;
static void *test_ops_ud;

void provision_set_ops_for_test(const provision_ops *ops, void *ud) {
    test_ops = ops;
    test_ops_ud = ud;
}

/* ------------------------------------------------------------------------- */
/* Production vtable                                                         */
/* ------------------------------------------------------------------------- */

static int prod_aws_init(void *ud, const char *profile, aws_ctx **out) {
    int rc;

    (void)ud;
    rc = aws_init(out, profile);
    if (rc != 0) {
        return rc;
    }
    aws_set_abort_hook(*out, cli_abort_check, NULL);
    return 0;
}

/* Test-only entry point for the production init seam. */
int provision_prod_aws_init_for_test(const char *profile, aws_ctx **out) {
    return prod_aws_init(NULL, profile, out);
}

static void prod_aws_free(void *ud, aws_ctx *aws) {
    (void)ud;
    aws_free(aws);
}

static int prod_cfn_create(void *ud, aws_ctx *aws, cfn_client **out) {
    (void)ud;
    return cfn_client_create(out, aws);
}

static void prod_cfn_destroy(void *ud, cfn_client *client) {
    (void)ud;
    cfn_client_destroy(client);
}

static int prod_describe(void *ud, cfn_client *client, const char *region,
                         const char *stack_name, cfn_stack_list *out) {
    (void)ud;
    return cfn_describe_stacks(client, region, stack_name, out);
}

static void prod_stack_list_free(void *ud, cfn_stack_list *list) {
    (void)ud;
    cfn_stack_list_free(list);
}

static int prod_create_cs(void *ud, cfn_client *client, const char *region,
                          const cfn_change_set_spec *spec,
                          cfn_change_set_result *out) {
    (void)ud;
    return cfn_create_change_set(client, region, spec, out);
}

static int prod_wait_cs(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs, int attempts,
                        int interval, int *timed_out, int *no_changes) {
    (void)ud;
    return cfn_wait_for_change_set(client, region, stack, cs, attempts, interval,
                                   timed_out, no_changes);
}

static int prod_desc_cs(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs,
                        cfn_change_set *out) {
    (void)ud;
    return cfn_describe_change_set(client, region, stack, cs, out);
}

static void prod_change_set_free(void *ud, cfn_change_set *cs) {
    (void)ud;
    cfn_change_set_free(cs);
}

static int prod_execute(void *ud, cfn_client *client, const char *region,
                        const char *stack, const char *cs) {
    (void)ud;
    return cfn_execute_change_set(client, region, stack, cs);
}

static int prod_delete_cs(void *ud, cfn_client *client, const char *region,
                          const char *stack, const char *cs) {
    (void)ud;
    return cfn_delete_change_set(client, region, stack, cs);
}

static int prod_wait_stack(void *ud, cfn_client *client, const char *region,
                           const char *stack, cfn_wait_operation op,
                           int attempts, int interval, int *timed_out) {
    (void)ud;
    return cfn_wait_for_stack(client, region, stack, op, attempts, interval,
                              timed_out);
}

static int prod_delete_stack(void *ud, cfn_client *client, const char *region,
                             const char *stack) {
    (void)ud;
    return cfn_delete_stack(client, region, stack);
}

/* --- IAM / credentials production seams --------------------------------- */

static int prod_iam_identity(void *ud, aws_ctx *ctx, char **out_arn) {
    char *account = NULL;
    char *user_id = NULL;
    int rc;

    (void)ud;
    rc = iam_get_caller_identity(ctx, &account, out_arn, &user_id);
    free(account);
    free(user_id);
    return rc;
}

static int prod_iam_list_keys(void *ud, aws_ctx *ctx, const char *user,
                              iam_key **out, size_t *out_count) {
    (void)ud;
    return iam_list_access_keys(ctx, user, out, out_count);
}

static int prod_iam_create_key(void *ud, aws_ctx *ctx, const char *user,
                               iam_key *out) {
    (void)ud;
    return iam_create_access_key(ctx, user, out);
}

static int prod_iam_delete_key(void *ud, aws_ctx *ctx, const char *user,
                               const char *key_id) {
    (void)ud;
    return iam_delete_access_key(ctx, user, key_id);
}

static void prod_iam_key_free(void *ud, iam_key *key) {
    (void)ud;
    iam_key_free(key);
}

static void prod_iam_keys_free(void *ud, iam_key *keys, size_t count) {
    (void)ud;
    iam_keys_free(keys, count);
}

static int credentials_path(char *out, size_t cap) {
    const char *home = getenv("HOME");
    int rc;

    if (home == NULL || home[0] == '\0') {
        return ENOENT;
    }
    rc = snprintf(out, cap, "%s/.aws/credentials", home);
    return rc < 0 || (size_t)rc >= cap ? ENAMETOOLONG : 0;
}

/*
 * Read the `aws_access_key_id` of `[profile]` from ~/.aws/credentials. A
 * missing file/profile yields success with *out = NULL (an absent key is not
 * an error). core/ini exposes only an upsert API, so the read side is local.
 */
static int prod_credentials_key_id(void *ud, const char *profile, char **out) {
    char path[PATH_MAX];
    FILE *file;
    char line[1024];
    int in_section = 0;
    int rc;

    (void)ud;
    *out = NULL;
    rc = credentials_path(path, sizeof(path));
    if (rc != 0) {
        return rc;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return errno == ENOENT ? 0 : (errno != 0 ? errno : EIO);
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *cursor = line;

        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        if (*cursor == '[') {
            char *close = strchr(cursor, ']');

            in_section = close != NULL &&
                         (size_t)(close - cursor - 1) == strlen(profile) &&
                         strncmp(cursor + 1, profile, strlen(profile)) == 0;
            continue;
        }
        if (in_section) {
            char *equals = strchr(cursor, '=');
            char *value;
            char *end;

            if (equals == NULL) {
                continue;
            }
            *equals = '\0';
            {
                char *key_end = cursor + strlen(cursor);

                while (key_end > cursor &&
                       (key_end[-1] == ' ' || key_end[-1] == '\t')) {
                    *--key_end = '\0';
                }
            }
            if (strcmp(cursor, "aws_access_key_id") != 0) {
                continue;
            }
            value = equals + 1;
            while (*value == ' ' || *value == '\t') {
                value++;
            }
            end = value + strlen(value);
            while (end > value && (end[-1] == '\n' || end[-1] == '\r' ||
                                   end[-1] == ' ' || end[-1] == '\t')) {
                *--end = '\0';
            }
            *out = strdup(value);
            fclose(file);
            return *out != NULL ? 0 : ENOMEM;
        }
    }
    fclose(file);
    return 0;
}

static int prod_credentials_write(void *ud, const char *profile,
                                  const char *key_id, const char *secret,
                                  char **backup_out) {
    char path[PATH_MAX];
    char *first_backup = NULL;
    char *second_backup = NULL;
    int rc;

    (void)ud;
    if (backup_out != NULL) {
        *backup_out = NULL;
    }
    rc = credentials_path(path, sizeof(path));
    if (rc != 0) {
        return rc;
    }
    rc = ini_upsert_section(path, profile, "aws_access_key_id", key_id,
                            &first_backup);
    if (rc == 0) {
        rc = ini_upsert_section(path, profile, "aws_secret_access_key", secret,
                                &second_backup);
    }
    if (backup_out != NULL) {
        /* Prefer the backup taken before the pair of writes. */
        *backup_out = first_backup != NULL ? first_backup : second_backup;
        if (first_backup != NULL) {
            free(second_backup);
        }
    } else {
        free(first_backup);
        free(second_backup);
    }
    return rc;
}

static void prod_retry_pause(void *ud) {
    (void)ud;
    (void)usleep(500 * 1000);
}

static int prod_read_template_path(void *ud, const char *path,
                                   char **body_out);

static int prod_read_template(void *ud, const char *repo_root, char **body_out) {
    char path[PATH_MAX];
    int rc;

    rc = snprintf(path, sizeof(path), "%s/deploy/stackctl-operator.yaml",
                  repo_root);
    if (rc < 0 || (size_t)rc >= sizeof(path)) {
        return ENAMETOOLONG;
    }
    return prod_read_template_path(ud, path, body_out);
}

static int prod_read_template_path(void *ud, const char *path,
                                   char **body_out) {
    FILE *file;
    long size;
    char *body;

    (void)ud;
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

static const provision_ops production_ops = {
    .aws_init = prod_aws_init,
    .aws_free = prod_aws_free,
    .cfn_create = prod_cfn_create,
    .cfn_destroy = prod_cfn_destroy,
    .describe_stacks = prod_describe,
    .stack_list_free = prod_stack_list_free,
    .create_change_set = prod_create_cs,
    .wait_change_set = prod_wait_cs,
    .describe_change_set = prod_desc_cs,
    .change_set_free = prod_change_set_free,
    .execute_change_set = prod_execute,
    .delete_change_set = prod_delete_cs,
    .wait_stack = prod_wait_stack,
    .delete_stack = prod_delete_stack,
    .iam_identity = prod_iam_identity,
    .iam_list_keys = prod_iam_list_keys,
    .iam_create_key = prod_iam_create_key,
    .iam_delete_key = prod_iam_delete_key,
    .iam_key_free = prod_iam_key_free,
    .iam_keys_free = prod_iam_keys_free,
    .credentials_key_id = prod_credentials_key_id,
    .credentials_write = prod_credentials_write,
    .retry_pause = prod_retry_pause,
    .read_template = prod_read_template,
    .read_template_path = prod_read_template_path,
};

/* ------------------------------------------------------------------------- */
/* Operator parameter union                                                  */
/* ------------------------------------------------------------------------- */

typedef struct operator_union {
    char types_amd64[512];
    char types_arm64[512];
    char buckets[128];
    char prefixes[512];
    int image_builder;
    int has_ci;
} operator_union;

static int csv_append_unique(char *csv, size_t cap, const char *value) {
    const char *start = value;
    size_t used = strlen(csv);

    while (*start != '\0') {
        const char *comma = strchr(start, ',');
        size_t len = comma != NULL ? (size_t)(comma - start) : strlen(start);
        const char *begin = start;
        char item[128];

        while (*begin == ' ' || *begin == '\t') {
            begin++;
            len--;
        }
        while (len > 0 && (begin[len - 1] == ' ' || begin[len - 1] == '\t')) {
            len--;
        }
        if (len > 0 && len < sizeof(item)) {
            memcpy(item, begin, len);
            item[len] = '\0';
            if (used > 0)
                strncat(csv, ",", cap - strlen(csv) - 1);
            if (strstr(csv, item) == NULL) {
                strncat(csv, item, cap - strlen(csv) - 1);
            }
            used = strlen(csv);
        }
        if (comma == NULL) {
            break;
        }
        start = comma + 1;
    }
    return 0;
}

static void union_merge_kv(operator_union *u, const char *key,
                           const char *value) {
    if (strcmp(key, "INSTANCE_TYPES_AMD64") == 0) {
        (void)csv_append_unique(u->types_amd64, sizeof(u->types_amd64), value);
    } else if (strcmp(key, "INSTANCE_TYPES_ARM64") == 0) {
        (void)csv_append_unique(u->types_arm64, sizeof(u->types_arm64), value);
    } else if (strcmp(key, "BUCKET_MODULES") == 0) {
        (void)csv_append_unique(u->buckets, sizeof(u->buckets), value);
    } else if (strcmp(key, "RELEASE_PREFIXES") == 0) {
        (void)csv_append_unique(u->prefixes, sizeof(u->prefixes), value);
        if (value[0] != '\0') {
            u->has_ci = 1;
        }
    } else if (strcmp(key, "ENABLE_IMAGE_BUILDER") == 0) {
        if (strcmp(value, "true") == 0) {
            u->image_builder = 1;
        }
    }
}

static void collect_union(const provision_env *env, operator_union *u) {
    DIR *dir;

    memset(u, 0, sizeof(*u));
    {
        const char *amd64 = config_get(env->cfg, "INSTANCE_TYPES_AMD64");
        const char *arm64 = config_get(env->cfg, "INSTANCE_TYPES_ARM64");
        const char *buckets = config_get(env->cfg, "BUCKET_MODULES");
        const char *prefixes = config_get(env->cfg, "RELEASE_PREFIXES");
        const char *builder = config_get(env->cfg, "ENABLE_IMAGE_BUILDER");

        if (amd64 != NULL)
            (void)csv_append_unique(u->types_amd64, sizeof(u->types_amd64),
                                    amd64);
        if (arm64 != NULL)
            (void)csv_append_unique(u->types_arm64, sizeof(u->types_arm64),
                                    arm64);
        if (buckets != NULL)
            (void)csv_append_unique(u->buckets, sizeof(u->buckets), buckets);
        if (prefixes != NULL) {
            (void)csv_append_unique(u->prefixes, sizeof(u->prefixes), prefixes);
            if (prefixes[0] != '\0')
                u->has_ci = 1;
        }
        if (builder != NULL && strcmp(builder, "true") == 0) {
            u->image_builder = 1;
        }
    }

    dir = opendir(env->config_dir);
    if (dir == NULL) {
        return;
    }
    for (struct dirent *entry = readdir(dir); entry != NULL;
         entry = readdir(dir)) {
        char path[PATH_MAX];
        char err[256];
        config_envfile *variant = NULL;

        if (strncmp(entry->d_name, ".env.", 5) != 0 ||
            strstr(entry->d_name, ".example") != NULL) {
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", env->config_dir,
                     entry->d_name) >= (int)sizeof(path)) {
            continue;
        }
        /* Consume the config module's parser, never a private .env reader. */
        if (config_envfile_load(path, &variant, err, sizeof err) != 0) {
            continue;
        }
        for (size_t i = 0; i < config_envfile_count(variant); i++) {
            union_merge_kv(u, config_envfile_key_at(variant, i),
                           config_envfile_value_at(variant, i));
        }
        config_envfile_free(variant);
    }
    closedir(dir);
}

/* ------------------------------------------------------------------------- */
/* Reporting                                                                 */
/* ------------------------------------------------------------------------- */

static void report_json(const provision_env *env, const char *stack,
                        const char *change_set, size_t changes, int executed) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root;

    if (doc == NULL) {
        return;
    }
    root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "verb", "provision");
    yyjson_mut_obj_add_str(doc, root, "stack", stack);
    yyjson_mut_obj_add_str(doc, root, "change_set", change_set);
    yyjson_mut_obj_add_uint(doc, root, "changes", changes);
    yyjson_mut_obj_add_bool(doc, root, "executed", executed != 0);
    yyjson_mut_obj_add_bool(doc, root, "dry_run", env->dry_run != 0);
    (void)cli_json_write(env->out != NULL ? env->out : stdout, doc);
    yyjson_mut_doc_free(doc);
}

/* ------------------------------------------------------------------------- */
/* Region variant + key lifecycle                                           */
/* ------------------------------------------------------------------------- */

static int read_primary_region(const char *config_dir, char *out, size_t cap) {
    char path[PATH_MAX];
    FILE *file;
    char line[1024];

    if (snprintf(path, sizeof(path), "%s/.env", config_dir) >=
        (int)sizeof(path)) {
        return ENAMETOOLONG;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return errno != 0 ? errno : ENOENT;
    }
    out[0] = '\0';
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "REGION=", 7) == 0) {
            char *value = line + 7;
            char *end = value + strlen(value);

            while (end > value && (end[-1] == '\n' || end[-1] == '\r')) {
                *--end = '\0';
            }
            snprintf(out, cap, "%s", value);
            break;
        }
    }
    fclose(file);
    return out[0] != '\0' ? 0 : ENOENT;
}

int provision_region_variant(const char *config_dir,
                             const stackctl_config *cfg) {
    char primary[64];

    if (config_dir == NULL || cfg == NULL) {
        return 1;
    }
    if (read_primary_region(config_dir, primary, sizeof(primary)) != 0) {
        return 1; /* no plain .env: this config can only be a variant */
    }
    return strcmp(primary, config_region(cfg)) != 0;
}

static int key_is_active(const iam_key *keys, size_t count,
                         const char *key_id) {
    if (key_id == NULL) {
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        if (keys[i].access_key_id != NULL &&
            strcmp(keys[i].access_key_id, key_id) == 0) {
            return keys[i].status != NULL && strcmp(keys[i].status, "Active") == 0;
        }
    }
    return 0;
}

static int delete_keys_except(const provision_ops *ops, void *ud,
                              aws_ctx *admin, const char *user,
                              const iam_key *keys, size_t count,
                              const char *keep_id) {
    for (size_t i = 0; i < count; i++) {
        int rc;

        if (keys[i].access_key_id == NULL) {
            continue;
        }
        if (keep_id != NULL && strcmp(keys[i].access_key_id, keep_id) == 0) {
            continue;
        }
        rc = ops->iam_delete_key(ud, admin, user, keys[i].access_key_id);
        if (rc != 0 && rc != ENOENT) {
            return rc;
        }
    }
    return 0;
}

static int arn_matches_user(const char *arn, const char *project) {
    char suffix[300];
    size_t arn_len;
    size_t suffix_len;

    if (arn == NULL) {
        return 0;
    }
    snprintf(suffix, sizeof(suffix), ":user/%s", project);
    arn_len = strlen(arn);
    suffix_len = strlen(suffix);
    return arn_len >= suffix_len &&
           strcmp(arn + arn_len - suffix_len, suffix) == 0;
}

/*
 * Verify the project caller identity, retrying InvalidClientTokenId (mapped to
 * EACCES by core/iam) up to 6 times for fresh-key eventual consistency.
 */
static int verify_project_identity(const provision_ops *ops, void *ud,
                                   const char *project, int attempts,
                                   int *identity_mismatch) {
    int rc = 0;

    for (int attempt = 0; attempt < attempts; attempt++) {
        aws_ctx *project_aws = NULL;
        char *arn = NULL;

        rc = ops->aws_init(ud, project, &project_aws);
        if (rc != 0) {
            return rc;
        }
        rc = ops->iam_identity(ud, project_aws, &arn);
        ops->aws_free(ud, project_aws);
        if (rc == 0) {
            if (!arn_matches_user(arn, project) && identity_mismatch != NULL) {
                *identity_mismatch = 1;
            }
            free(arn);
            return 0;
        }
        free(arn);
        if (rc != EACCES || attempt + 1 >= attempts) {
            return rc;
        }
        if (ops->retry_pause != NULL) {
            ops->retry_pause(ud);
        }
    }
    return rc;
}

static int ensure_user_key(const provision_env *env, const provision_ops *ops,
                           void *ud, aws_ctx *admin, const char *project,
                           const char *user, const char *profile,
                           int rotate, int is_operator,
                           int *identity_mismatch) {
    char *local_key = NULL;
    iam_key *keys = NULL;
    size_t count = 0;
    size_t created_count = 0;
    int rc;

    rc = ops->credentials_key_id(ud, profile, &local_key);
    if (rc != 0) {
        return rc;
    }
    rc = ops->iam_list_keys(ud, admin, user, &keys, &count);
    if (rc != 0) {
        free(local_key);
        return rc;
    }

    {
        int have_local = local_key != NULL && local_key[0] != '\0';
        int local_live = have_local && key_is_active(keys, count, local_key);
        int create_key = rotate;

        if (is_operator) {
            if (!rotate && (!have_local || !local_live)) {
                fprintf(env->err,
                        "stackctl: warning: minting a new key for %s "
                        "invalidates the operator key on other machines\n",
                        project);
                create_key = 1;
            }
        } else if (!rotate) {
            if (count == 0) {
                create_key = 1;
            } else if (!have_local) {
                fprintf(env->err,
                        "stackctl: warning: CI key exists in IAM but not "
                        "locally — left intact; use --rotate-ci\n");
            }
        }

        if (!create_key) {
            /* Reuse: enforce the exactly-one invariant by removing extras. */
            rc = local_live ? delete_keys_except(ops, ud, admin, user, keys,
                                                 count, local_key)
                            : 0;
        } else {
            iam_key created = {0};
            char *backup = NULL;

            /* Prune-before-create keeps the two-key IAM limit safe. */
            rc = delete_keys_except(ops, ud, admin, user, keys, count,
                                    have_local ? local_key : NULL);
            if (rc == 0) {
                rc = ops->iam_create_key(ud, admin, user, &created);
            }
            if (rc == 0) {
                created_count = 1;
                rc = ops->credentials_write(ud, profile, created.access_key_id,
                                            created.secret_access_key, &backup);
            }
            free(backup);
            ops->iam_key_free(ud, &created);
        }
        if (rc == 0 && is_operator) {
            rc = verify_project_identity(ops, ud, project,
                                         created_count != 0 ? 6 : 1,
                                         identity_mismatch);
        }
        /* Under rotation the previous local key is deleted only after the
         * project identity check passes. */
        if (rc == 0 && create_key && have_local && local_key != NULL) {
            rc = ops->iam_delete_key(ud, admin, user, local_key);
            if (rc == ENOENT) {
                rc = 0;
            }
        }
    }

    ops->iam_keys_free(ud, keys, count);
    free(local_key);
    return rc;
}

int provision_ensure_keys(const provision_env *env, const provision_ops *ops,
                          void *ud, aws_ctx *admin_aws,
                          int *identity_mismatch) {
    const char *project;
    char ci_user[256];
    char ci_profile[256];
    int rc;

    if (env == NULL || ops == NULL || admin_aws == NULL || env->cfg == NULL) {
        return EINVAL;
    }
    if (ops->iam_list_keys == NULL || ops->iam_create_key == NULL ||
        ops->iam_delete_key == NULL || ops->credentials_key_id == NULL ||
        ops->credentials_write == NULL) {
        return EINVAL;
    }
    project = config_project(env->cfg);
    rc = ensure_user_key(env, ops, ud, admin_aws, project, project, project,
                         env->rotate, 1, identity_mismatch);
    if (rc != 0) {
        return rc;
    }
    snprintf(ci_user, sizeof(ci_user), "%s-ci", project);
    snprintf(ci_profile, sizeof(ci_profile), "%s-ci", project);
    return ensure_user_key(env, ops, ud, admin_aws, project, ci_user, ci_profile,
                           env->rotate_ci, 0, identity_mismatch);
}

/* ------------------------------------------------------------------------- */
/* Verb body                                                                 */
/* ------------------------------------------------------------------------- */

static int status_is_healthy(cfn_stack_status status) {
    return status == CFN_STACK_STATUS_CREATE_COMPLETE ||
           status == CFN_STACK_STATUS_UPDATE_COMPLETE ||
           status == CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE;
}

static void add_param(cfn_parameter *params, size_t *count, const char *key,
                      const char *value) {
    snprintf(params[*count].key, sizeof(params[*count].key), "%s", key);
    snprintf(params[*count].value, sizeof(params[*count].value), "%s", value);
    (*count)++;
}

int provision_run(const provision_env *env) {
    const provision_ops *ops;
    void *ud;
    const char *project;
    const char *region;
    char stack[CFN_STACK_NAME_MAX];
    char change_set_name[CFN_CHANGE_SET_NAME_MAX];
    char repo_root[PATH_MAX];
    char template_path[PATH_MAX];
    char *allocated_root = NULL;
    char *template_body = NULL;
    aws_ctx *aws = NULL;
    cfn_client *client = NULL;
    cfn_stack_list stacks = {0};
    cfn_change_set_type type = CFN_CHANGE_SET_TYPE_CREATE;
    int prior_review = 0;
    int ci_was_enabled = 0;
    operator_union union_cfg;
    cfn_parameter params[8] = {0};
    size_t param_count = 0;
    cfn_change_set_spec spec = {0};
    cfn_change_set_result result = {0};
    cfn_change_set change_set = {0};
    int timed_out = 0;
    int no_changes = 0;
    int rc;

    if (env == NULL || env->cfg == NULL || env->config_dir == NULL) {
        return CLI_EXIT_USAGE;
    }
    if (env->region_variant != 0) {
        fprintf(env->err,
                "stackctl: provision runs only from the primary config "
                "(plain .env); drop --region\n");
        return CLI_EXIT_USAGE;
    }
    ops = env->ops != NULL ? env->ops : test_ops;
    ud = env->ops_ud != NULL ? env->ops_ud : test_ops_ud;
    if (ops == NULL) {
        ops = &production_ops;
        ud = NULL;
    }

    project = config_project(env->cfg);
    region = config_region(env->cfg);
    snprintf(stack, sizeof(stack), "%s-operator", project);
    snprintf(change_set_name, sizeof(change_set_name), "%s-operator-provision",
             project);

    rc = config_repo_root(env->config_dir, &allocated_root);
    if (rc == 0) {
        snprintf(repo_root, sizeof(repo_root), "%s", allocated_root);
        free(allocated_root);
    } else {
        snprintf(repo_root, sizeof(repo_root), "%s", ".");
    }

    /*
     * §6.3 structural contract, fail-closed before any AWS call. TEMPLATE_OVERRIDE
     * is infra-only (deploy); provision always validates the canonical operator
     * template, so there is no operator override path to resolve.
     */
    if (ops->read_template_path != NULL) {
        int written = snprintf(template_path, sizeof(template_path),
                               "%s/deploy/stackctl-operator.yaml", repo_root);

        if (written < 0 || (size_t)written >= sizeof(template_path)) {
            fprintf(env->err,
                    "stackctl: cannot resolve the operator template path\n");
            return CLI_EXIT_USAGE;
        }
        rc = ops->read_template_path(ud, template_path, &template_body);
        if (rc != 0) {
            fprintf(env->err,
                    "stackctl: cannot read the operator template %s\n",
                    template_path);
            return CLI_EXIT_USAGE;
        }
        rc = tc_check_buffer(template_path, template_body,
                             strlen(template_body), TC_MODE_OPERATOR);
        if (rc != 0) {
            fprintf(env->err,
                    "stackctl: template %s violates the §6.3 contract\n",
                    template_path);
            free(template_body);
            return CLI_EXIT_USAGE;
        }
    } else {
        /* Legacy test seam: no real path to name in diagnostics. */
        rc = ops->read_template(ud, repo_root, &template_body);
        if (rc != 0) {
            fprintf(env->err, "stackctl: cannot read the operator template\n");
            return CLI_EXIT_USAGE;
        }
    }

    rc = ops->aws_init(ud, "default", &aws);
    if (rc != 0) {
        fprintf(env->err,
                "stackctl: cannot authenticate as the [default] admin "
                "profile\n");
        free(template_body);
        return CLI_EXIT_USAGE;
    }
    rc = ops->cfn_create(ud, aws, &client);
    if (rc != 0) {
        ops->aws_free(ud, aws);
        free(template_body);
        return CLI_EXIT_AWS;
    }

    rc = ops->describe_stacks(ud, client, region, stack, &stacks);
    if (rc == ENOENT || (rc == 0 && stacks.count == 0)) {
        type = CFN_CHANGE_SET_TYPE_CREATE;
    } else if (rc != 0) {
        fprintf(env->err, "stackctl: cannot describe %s\n", stack);
        rc = CLI_EXIT_AWS;
        goto done;
    } else {
        cfn_stack_status status = stacks.items[0].status;

        if (cfn_stack_status_is_in_progress(status)) {
            fprintf(env->err,
                    "stackctl: another operation is in progress on %s; "
                    "re-run later\n",
                    stack);
            rc = CLI_EXIT_AWS;
            goto done;
        }
        if (status_is_healthy(status)) {
            type = CFN_CHANGE_SET_TYPE_UPDATE;
        } else if (status == CFN_STACK_STATUS_REVIEW_IN_PROGRESS) {
            type = CFN_CHANGE_SET_TYPE_CREATE;
            prior_review = 1;
        } else if (status == CFN_STACK_STATUS_ROLLBACK_COMPLETE) {
            fprintf(env->err,
                    "stackctl: %s is in ROLLBACK_COMPLETE (failed create); "
                    "delete the stack, then re-run provision\n",
                    stack);
            rc = CLI_EXIT_AWS;
            goto done;
        } else if (status == CFN_STACK_STATUS_UPDATE_ROLLBACK_FAILED) {
            fprintf(env->err,
                    "stackctl: %s is in UPDATE_ROLLBACK_FAILED; run "
                    "`aws cloudformation continue-update-rollback` (manual)\n",
                    stack);
            rc = CLI_EXIT_AWS;
            goto done;
        } else if (status == CFN_STACK_STATUS_DELETE_FAILED) {
            fprintf(env->err,
                    "stackctl: %s is in DELETE_FAILED; inspect and remove the "
                    "failed resources, then re-run\n",
                    stack);
            rc = CLI_EXIT_AWS;
            goto done;
        } else {
            fprintf(env->err, "stackctl: %s is in %s; refusing to proceed\n",
                    stack, cfn_stack_status_string(status));
            rc = CLI_EXIT_AWS;
            goto done;
        }
    }

    collect_union(env, &union_cfg);
    /*
     * F5: an existing CiUser output proves the stack had CI enabled. Clearing
     * RELEASE_PREFIXES deletes that user and invalidates its access keys, so
     * the change-set summary warns about the one-way transition.
     */
    if (stacks.count > 0) {
        const char *ci_output =
            cfn_stack_output(&stacks.items[0], "CiUserName");

        /* Presence is unconditional: the output is "-" when CI is off, so the
         * warning must key on a real user name, not on the output's existence.
         * A missing output stays silent (no proof CI was ever enabled). */
        ci_was_enabled =
            ci_output != NULL && strcmp(ci_output, "-") != 0;
    }

    add_param(params, &param_count, "ProjectName", project);
    add_param(params, &param_count, "InstanceTypeAllowlist",
              union_cfg.types_amd64[0] != '\0' ? union_cfg.types_amd64
                                               : union_cfg.types_arm64);
    add_param(params, &param_count, "EnableImageBuilder",
              union_cfg.image_builder != 0 ? "true" : "false");
    add_param(params, &param_count, "EnableCiUser",
              union_cfg.has_ci != 0 ? "true" : "false");
    if (union_cfg.has_ci != 0) {
        add_param(params, &param_count, "ReleasePrefixes", union_cfg.prefixes);
    }
    /* F6: same membership test the infra stack uses (deploy.c). */
    add_param(params, &param_count, "CertBucketEnabled",
              strstr(union_cfg.buckets, "cert") != NULL ? "true" : "false");
    {
        const char *boundary = config_get(env->cfg, "PERMISSIONS_BOUNDARY_ARN");

        if (boundary != NULL) {
            add_param(params, &param_count, "PermissionsBoundaryArn", boundary);
        }
    }

    spec.stack_name = stack;
    spec.change_set_name = change_set_name;
    spec.template_body = template_body;
    spec.type = type;
    spec.parameters = params;
    spec.parameter_count = param_count;
    spec.description = "stackctl provision";
    spec.capabilities = CFN_CAPABILITY_NAMED_IAM;

    rc = ops->create_change_set(ud, client, region, &spec, &result);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot create the change set for %s\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }
    rc = ops->wait_change_set(ud, client, region, stack, change_set_name, 120,
                              5, &timed_out, &no_changes);
    if (rc != 0 || timed_out != 0) {
        fprintf(env->err, "stackctl: change set for %s did not complete\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }
    if (no_changes != 0) {
        /*
         * The stack already conforms. Clean up the empty change set and treat
         * the stack step as a success so the key lifecycle below still runs:
         * a conforming stack with zero operator keys must still mint them.
         */
        (void)ops->delete_change_set(ud, client, region, stack,
                                     change_set_name);
        if (prior_review != 0) {
            (void)ops->delete_stack(ud, client, region, stack);
        }
        goto ensure_credentials;
    }
    rc = ops->describe_change_set(ud, client, region, stack, change_set_name,
                                  &change_set);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot describe the change set for %s\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }

    if (change_set.change_count == 0) {
        (void)ops->delete_change_set(ud, client, region, stack,
                                     change_set_name);
        if (prior_review != 0) {
            (void)ops->delete_stack(ud, client, region, stack);
        }
        if (env->json != 0) {
            report_json(env, stack, change_set_name, 0, 0);
        } else {
            fprintf(env->out, "%s: no changes\n", stack);
        }
        rc = CLI_EXIT_OK;
        goto done;
    }

    if (env->json == 0) {
        fprintf(env->out, "%s: %zu change(s) in the change set\n", stack,
                change_set.change_count);
    }

    /* F5: warn on the one-way true->false CI-user transition. */
    if (ci_was_enabled != 0 && union_cfg.has_ci == 0) {
        fprintf(env->err,
                "stackctl: warning: RELEASE_PREFIXES is empty; this change "
                "deletes CiUser and invalidates its access keys\n");
    }

    if (env->dry_run != 0) {
        (void)ops->delete_change_set(ud, client, region, stack,
                                     change_set_name);
        if (prior_review != 0) {
            (void)ops->delete_stack(ud, client, region, stack);
        }
        if (env->json != 0) {
            report_json(env, stack, change_set_name, change_set.change_count, 0);
        } else {
            fprintf(env->out, "dry-run: change set deleted, nothing applied\n");
        }
        rc = CLI_EXIT_OK;
        goto done;
    }

    {
        int decision = env->confirm != NULL
                           ? env->confirm(env->confirm_ud, "apply? [y/N] ")
                           : CLI_CONFIRM_NONINTERACTIVE;

        if (decision == CLI_CONFIRM_NONINTERACTIVE ||
            decision == CLI_CONFIRM_EOF) {
            (void)ops->delete_change_set(ud, client, region, stack,
                                         change_set_name);
            if (prior_review != 0) {
                (void)ops->delete_stack(ud, client, region, stack);
            }
            fprintf(env->err,
                    "stackctl: refusing to apply non-interactively without "
                    "--yes\n");
            rc = CLI_EXIT_USAGE;
            goto done;
        }
        if (decision != CLI_CONFIRM_YES) {
            (void)ops->delete_change_set(ud, client, region, stack,
                                         change_set_name);
            if (prior_review != 0) {
                (void)ops->delete_stack(ud, client, region, stack);
            }
            if (env->json != 0) {
                report_json(env, stack, change_set_name,
                            change_set.change_count, 0);
            } else {
                fprintf(env->out, "aborted; change set deleted\n");
            }
            rc = CLI_EXIT_OK;
            goto done;
        }
    }

    rc = ops->execute_change_set(ud, client, region, stack, change_set_name);
    if (rc != 0) {
        fprintf(env->err, "stackctl: failed to execute the change set for %s\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }
    timed_out = 0;
    rc = ops->wait_stack(ud, client, region, stack,
                         type == CFN_CHANGE_SET_TYPE_CREATE ? CFN_WAIT_CREATE
                                                            : CFN_WAIT_UPDATE,
                         180, 5, &timed_out);
    if (rc != 0 || timed_out != 0) {
        fprintf(env->err,
                "stackctl: stack operation on %s did not complete; stack "
                "operation continues server-side; run `stackctl status`\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }

ensure_credentials:
    {
        int mismatch = 0;

        rc = provision_ensure_keys(env, ops, ud, aws, &mismatch);
        if (mismatch != 0) {
            fprintf(env->err,
                    "stackctl: identity guard failed: caller is not "
                    ":user/%s\n",
                    project);
            rc = CLI_EXIT_VERIFY;
            goto done;
        }
        if (rc != 0) {
            fprintf(env->err, "stackctl: credential/identity step failed\n");
            rc = CLI_EXIT_AWS;
            goto done;
        }
    }

    if (env->json != 0) {
        report_json(env, stack, change_set_name, change_set.change_count, 1);
    } else {
        fprintf(env->out, "%s: provisioned (%zu change(s))\n", stack,
                change_set.change_count);
    }
    rc = CLI_EXIT_OK;

done:
    ops->change_set_free(ud, &change_set);
    ops->stack_list_free(ud, &stacks);
    ops->cfn_destroy(ud, client);
    ops->aws_free(ud, aws);
    free(template_body);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Public entry point                                                        */
/* ------------------------------------------------------------------------- */

static int confirm_with_ctx(void *ud, const char *prompt) {
    return cli_confirm((cli_ctx *)ud, prompt);
}

static void log_outcome(cli_ctx *ctx, int code) {
    state_store *store = cli_ctx_state(ctx);
    char args[512];
    char outcome[32];
    char **argv = cli_ctx_verb_argv(ctx);
    int argc = cli_ctx_verb_argc(ctx);

    if (store == NULL) {
        return;
    }
    if (cli_redact_args((const char *const *)argv, (size_t)argc, args,
                        sizeof(args)) != 0) {
        snprintf(args, sizeof(args), "provision");
    }
    snprintf(outcome, sizeof(outcome), "%s",
             code == CLI_EXIT_OK ? "success" : "failure");
    (void)state_operations_log_append(store, "provision", args, outcome);
}

int cli_cmd_provision(cli_ctx *ctx) {
    static const cli_option_spec specs[] = {
        {"rotate", 0, 0, 0, NULL, "rotate the operator key"},
        {"rotate-ci", 0, 0, 0, NULL, "rotate the CI key"},
    };
    cli_args args = {0};
    provision_env env = {0};
    int rc;

    if (ctx == NULL) {
        return cli_fail(NULL, CLI_EXIT_USAGE, "provision: no context");
    }
    rc = cli_ctx_parse_args(ctx, specs, sizeof(specs) / sizeof(specs[0]),
                            &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "provision: invalid arguments");
    }
    if (args.positional_count != 0) {
        cli_args_free(&args);
        return cli_fail(ctx, CLI_EXIT_USAGE,
                        "provision does not take positional arguments");
    }
    env.rotate = cli_args_flag(&args, "rotate");
    env.rotate_ci = cli_args_flag(&args, "rotate-ci");
    cli_args_free(&args);

    env.cfg = cli_ctx_config(ctx);
    env.config_dir = config_dir(env.cfg);
    if (env.config_dir == NULL) {
        return cli_fail(ctx, CLI_EXIT_USAGE,
                        "provision: cannot locate the project config "
                        "directory");
    }
    env.region_variant = provision_region_variant(env.config_dir, env.cfg);
    env.yes = cli_ctx_yes(ctx);
    env.dry_run = cli_ctx_dry_run(ctx);
    env.json = cli_ctx_json(ctx);
    env.out = stdout;
    env.err = stderr;
    env.ops = NULL;
    env.ops_ud = NULL;
    env.confirm = confirm_with_ctx;
    env.confirm_ud = ctx;

    rc = provision_run(&env);
    log_outcome(ctx, rc);
    return rc;
}
