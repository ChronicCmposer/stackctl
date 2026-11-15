/*
 * deploy.c — `stackctl deploy` (spec §4 deploy, §7 release model).
 *
 * Pipeline: provenance gate -> freshness gate (unless --skip-build/rollback) ->
 * AMI-region preflight -> release publish or immutable-tag verification ->
 * infra-stack change set with preview + confirmation -> execute/wait -> record
 * the release in state. Rollback is `deploy --tag <vX.Y.Z>` against an existing
 * verified release.
 */

#include "deploy_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "core/aws/aws.h"
#include "core/crypto/crypto.h"
#include "core/ec2/ec2.h"
#include "core/s3/s3.h"
#include "core/ssm/ssm.h"
#include "iam.h"
#include "yyjson.h"

/* ------------------------------------------------------------------------- */
/* Test seam                                                                 */
/* ------------------------------------------------------------------------- */

static const deploy_ops *test_ops;
static void *test_ops_ud;

/* Production stage context: the project identity and target region. */
struct prod_context {
    const char *project;
    const char *region;
    const char *bazel;
};

void deploy_set_ops_for_test(const deploy_ops *ops, void *ud) {
    test_ops = ops;
    test_ops_ud = ud;
}

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

typedef struct buffer {
    char *data;
    size_t len;
    size_t cap;
} buffer;

static int buffer_append(buffer *buf, const char *text, size_t len) {
    size_t need = buf->len + len + 1;

    if (need > buf->cap) {
        size_t cap = buf->cap != 0 ? buf->cap : 512;
        char *grown;

        while (cap < need) {
            cap *= 2;
        }
        grown = realloc(buf->data, cap);
        if (grown == NULL) {
            return ENOMEM;
        }
        buf->data = grown;
        buf->cap = cap;
    }
    memcpy(buf->data + buf->len, text, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

static void sha256_hex(const void *data, size_t len, char out[65]) {
    uint8_t digest[32];
    static const char hex[] = "0123456789abcdef";

    crypto_sha256(data, len, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
}

static int run_capture(const char *command, char **out) {
    FILE *pipe = popen(command, "r");
    buffer captured = {0};
    char chunk[512];
    size_t n;
    int status;

    if (pipe == NULL) {
        return errno != 0 ? errno : EIO;
    }
    while ((n = fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
        if (buffer_append(&captured, chunk, n) != 0) {
            pclose(pipe);
            free(captured.data);
            return ENOMEM;
        }
    }
    status = pclose(pipe);
    if (status == -1) {
        free(captured.data);
        return errno != 0 ? errno : EIO;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        free(captured.data);
        return EIO;
    }
    if (captured.data == NULL) {
        captured.data = strdup("");
        if (captured.data == NULL) {
            return ENOMEM;
        }
    }
    *out = captured.data;
    return 0;
}

/* Return the first whitespace-delimited token of `text`, or NULL. */
static char *first_token(char *text) {
    char *start = text;

    while (*start == ' ' || *start == '\t' || *start == '\n') {
        start++;
    }
    if (*start == '\0') {
        return NULL;
    }
    {
        char *end = start;

        while (*end != '\0' && *end != ' ' && *end != '\t' && *end != '\n') {
            end++;
        }
        *end = '\0';
    }
    return start;
}

static int tag_is_semver(const char *tag) {
    int dots = 0;

    if (tag == NULL || tag[0] != 'v') {
        return 0;
    }
    for (const char *p = tag + 1; *p != '\0'; p++) {
        if (*p == '.') {
            dots++;
        } else if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    return dots == 2;
}

/*
 * Copy `in` into `out` as a POSIX single-quoted word, replacing each embedded
 * `'` with `'\''`. Returns 0 or ENAMETOOLONG (out is never left unterminated).
 */
int deploy_shell_quote(const char *in, char *out, size_t cap) {
    size_t used = 0;

    if (in == NULL || out == NULL || cap == 0) {
        return EINVAL;
    }
    out[used++] = '\'';
    for (const char *p = in; *p != '\0'; p++) {
        if (*p == '\'') {
            static const char escaped[] = "'\\''";
            if (used + sizeof(escaped) > cap) {
                out[cap - 1] = '\0';
                return ENAMETOOLONG;
            }
            memcpy(out + used, escaped, sizeof(escaped) - 1);
            used += sizeof(escaped) - 1;
        } else {
            if (used + 2 > cap) {
                out[cap - 1] = '\0';
                return ENAMETOOLONG;
            }
            out[used++] = *p;
        }
    }
    if (used + 2 > cap) {
        out[cap - 1] = '\0';
        return ENAMETOOLONG;
    }
    out[used++] = '\'';
    out[used] = '\0';
    return 0;
}

int deploy_manifest_line(const char *sha, const char *member, char *out,
                         size_t cap) {
    int rc;

    if (sha == NULL || member == NULL || out == NULL) {
        return EINVAL;
    }
    rc = snprintf(out, cap, "%s  %s\n", sha, member);
    return rc < 0 || (size_t)rc >= cap ? ENAMETOOLONG : 0;
}

int deploy_iso8601_to_epoch(const char *iso, long long *out) {
    struct tm tm = {0};
    long long epoch;

    if (iso == NULL || out == NULL) {
        return EINVAL;
    }
    if (sscanf(iso, "%4d-%2d-%2dT%2d:%2d:%2d", &tm.tm_year, &tm.tm_mon,
               &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
        return EINVAL;
    }
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    epoch = (long long)timegm(&tm);
    if (epoch < 0) {
        return EINVAL;
    }
    *out = epoch;
    return 0;
}

static int is_protected_tag(const deploy_release_entry *entry,
                            const char *pinned, const char *previous,
                            const char *just_uploaded) {
    return (pinned != NULL && strcmp(entry->tag, pinned) == 0) ||
           (previous != NULL && strcmp(entry->tag, previous) == 0) ||
           (just_uploaded != NULL && strcmp(entry->tag, just_uploaded) == 0);
}

size_t deploy_prune_mark(deploy_release_entry *entries, size_t count,
                         const char *pinned, const char *previous,
                         const char *just_uploaded, long long now_epoch) {
    size_t marked = 0;
    size_t manifest_count = 0;
    size_t *order;
    const long long garbage_cutoff = 24LL * 60 * 60;

    if (entries == NULL) {
        return 0;
    }
    order = calloc(count != 0 ? count : 1, sizeof(*order));
    if (order == NULL) {
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        entries[i].delete_me = 0;
        if (entries[i].manifest_epoch > 0) {
            size_t pos = manifest_count++;
            while (pos > 0 &&
                   entries[order[pos - 1]].manifest_epoch <
                       entries[i].manifest_epoch) {
                order[pos] = order[pos - 1];
                pos--;
            }
            order[pos] = i;
        }
    }
    for (size_t rank = 0; rank < manifest_count; rank++) {
        deploy_release_entry *entry = &entries[order[rank]];
        if (rank >= 10 && !is_protected_tag(entry, pinned, previous,
                                            just_uploaded)) {
            entry->delete_me = 1;
            marked++;
        }
    }
    for (size_t i = 0; i < count; i++) {
        deploy_release_entry *entry = &entries[i];
        if (entry->delete_me != 0 || entry->manifest_epoch > 0 ||
            is_protected_tag(entry, pinned, previous, just_uploaded)) {
            continue;
        }
        if (entry->newest_epoch > 0 &&
            now_epoch - entry->newest_epoch > garbage_cutoff) {
            entry->delete_me = 1;
            marked++;
        }
    }
    free(order);
    return marked;
}

static int ssm_fetch(const char *profile, const char *region, const char *name,
                     char *out, size_t cap) {
    aws_ctx *aws = NULL;
    ssm_client *client = NULL;
    ssm_parameter parameter = {0};
    int rc;

    rc = aws_init(&aws, profile);
    if (rc != 0) {
        return rc;
    }
    rc = ssm_client_init(&client, aws, region);
    if (rc == 0) {
        rc = ssm_get_parameter(client, name, 0, &parameter);
    }
    if (rc == 0) {
        snprintf(out, cap, "%s",
                 parameter.value != NULL ? parameter.value : "");
    }
    ssm_parameter_free(&parameter);
    ssm_client_free(client);
    aws_free(aws);
    return rc;
}

static int s3_open(const char *profile, const char *region, aws_ctx **aws_out,
                   s3_client **client_out) {
    aws_ctx *aws = NULL;
    s3_client *client = NULL;
    int rc;

    rc = aws_init(&aws, profile);
    if (rc != 0) {
        return rc;
    }
    rc = s3_client_init(&client, aws, region);
    if (rc != 0) {
        aws_free(aws);
        return rc;
    }
    *aws_out = aws;
    *client_out = client;
    return 0;
}

static void s3_close(aws_ctx *aws, s3_client *client) {
    s3_client_free(client);
    aws_free(aws);
}

static int make_camel_arch(const char *arch, char *out, size_t cap) {
    size_t used = 0;
    int rc = snprintf(out, cap, "AmiId");

    if (rc < 0 || (size_t)rc >= cap) {
        return ENAMETOOLONG;
    }
    used = (size_t)rc;
    for (size_t i = 0; arch[i] != '\0'; i++) {
        char c = arch[i];

        if (i == 0 && c >= 'a' && c <= 'z') {
            c = (char)(c - 'a' + 'A');
        }
        if (used + 1 >= cap) {
            return ENAMETOOLONG;
        }
        out[used++] = c;
    }
    out[used] = '\0';
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Production stages                                                         */
/* ------------------------------------------------------------------------- */

static int prod_provenance(void *ud, const char *repo_root, int allow_dirty,
                           char *tag, size_t cap) {
    char command[PATH_MAX * 4];
    char quoted_root[PATH_MAX * 2];
    char *tags = NULL;
    char *cursor;
    char selected[128] = {0};
    int found = 0;
    int rc;

    (void)ud;
    if (deploy_shell_quote(repo_root, quoted_root, sizeof(quoted_root)) != 0) {
        return CLI_EXIT_VERIFY;
    }
    rc = snprintf(command, sizeof(command),
                  "git -C %s tag --points-at HEAD", quoted_root);
    if (rc < 0 || (size_t)rc >= sizeof(command)) {
        return CLI_EXIT_VERIFY;
    }
    if (run_capture(command, &tags) != 0) {
        return CLI_EXIT_VERIFY;
    }
    cursor = tags;
    while (cursor != NULL && *cursor != '\0') {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');

        if (newline != NULL) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor = NULL;
        }
        if (tag_is_semver(line)) {
            if (found == 0) {
                snprintf(selected, sizeof(selected), "%s", line);
            }
            found++;
        }
    }
    free(tags);
    if (found == 0) {
        return CLI_EXIT_VERIFY;
    }
    if (found > 1) {
        return CLI_EXIT_USAGE;
    }

    /* The tag must be annotated. */
    rc = snprintf(command, sizeof(command), "git -C %s cat-file -t '%s'",
                  quoted_root, selected);
    if (rc < 0 || (size_t)rc >= sizeof(command)) {
        return CLI_EXIT_VERIFY;
    }
    {
        char *kind = NULL;

        if (run_capture(command, &kind) != 0) {
            return CLI_EXIT_VERIFY;
        }
        {
            char *token = first_token(kind);
            int annotated = token != NULL && strcmp(token, "tag") == 0;

            free(kind);
            if (!annotated) {
                return CLI_EXIT_VERIFY;
            }
        }
    }

    if (!allow_dirty) {
        rc = snprintf(command, sizeof(command),
                      "git -C %s status --porcelain", quoted_root);
        if (rc < 0 || (size_t)rc >= sizeof(command)) {
            return CLI_EXIT_VERIFY;
        }
        {
            char *status = NULL;

            if (run_capture(command, &status) != 0) {
                return CLI_EXIT_VERIFY;
            }
            if (status[0] != '\0') {
                free(status);
                return CLI_EXIT_VERIFY;
            }
            free(status);
        }
    }

    {
        char head_command[PATH_MAX * 2];
        char remote_command[PATH_MAX * 2];
        char *head = NULL;
        char *remote = NULL;
        char *head_token;
        int matches = 0;

        snprintf(head_command, sizeof(head_command),
                 "git -C %s rev-parse HEAD", quoted_root);
        if (run_capture(head_command, &head) != 0) {
            return CLI_EXIT_VERIFY;
        }
        head_token = first_token(head);
        if (head_token == NULL) {
            free(head);
            return CLI_EXIT_VERIFY;
        }
        snprintf(remote_command, sizeof(remote_command),
                 "git -C %s ls-remote origin 'refs/tags/%s' "
                 "'refs/tags/%s^{}'",
                 quoted_root, selected, selected);
        if (run_capture(remote_command, &remote) == 0) {
            char *line = remote;

            while (*line != '\0') {
                char *newline = strchr(line, '\n');
                char *token;

                if (newline != NULL) {
                    *newline = '\0';
                }
                token = first_token(line);
                if (token != NULL && strcmp(token, head_token) == 0) {
                    matches = 1;
                }
                if (newline == NULL) {
                    break;
                }
                line = newline + 1;
            }
            free(remote);
        }
        free(head);
        if (!matches) {
            return CLI_EXIT_VERIFY;
        }
    }

    snprintf(tag, cap, "%s", selected);
    return 0;
}

static int prod_freshness(void *ud, const char *repo_root,
                          const char *targets) {
    const struct prod_context *ctx = ud;
    const char *bazel = ctx != NULL && ctx->bazel != NULL ? ctx->bazel
                                                           : "bazel";
    char command[PATH_MAX * 4];
    char quoted_root[PATH_MAX * 2];
    int rc;

    if (deploy_shell_quote(repo_root, quoted_root, sizeof(quoted_root)) != 0) {
        return CLI_EXIT_FRESHNESS;
    }
    rc = snprintf(command, sizeof(command),
                  "cd %s && '%s' cquery --output=files %s >/dev/null 2>&1 "
                  "&& '%s' build --check_up_to_date %s >/dev/null 2>&1",
                  quoted_root, bazel, targets, bazel, targets);
    if (rc < 0 || (size_t)rc >= sizeof(command)) {
        return CLI_EXIT_FRESHNESS;
    }
    return system(command) == 0 ? 0 : CLI_EXIT_FRESHNESS;
}

static int prod_bucket(void *ud, const char *project, const char *region,
                       char *out, size_t cap) {
    aws_ctx *aws = NULL;
    char *account = NULL;
    char *arn = NULL;
    char *user_id = NULL;
    int rc;

    (void)ud;
    rc = aws_init(&aws, project);
    if (rc != 0) {
        return rc;
    }
    rc = iam_get_caller_identity(aws, &account, &arn, &user_id);
    if (rc == 0) {
        snprintf(out, cap, "%s-artifacts-%s-%s", project,
                 account != NULL ? account : "", region);
    }
    free(account);
    free(arn);
    free(user_id);
    aws_free(aws);
    return rc;
}

static int prod_resolve_ami(void *ud, const stackctl_config *cfg,
                            const char *region, const char *arch, char *out,
                            size_t cap) {
    const char *policy = config_get(cfg, "AMI_POLICY");
    char key[64];
    char suffix[16];
    const char *value;

    (void)ud;
    snprintf(suffix, sizeof(suffix), "%s",
             strcmp(arch, "amd64") == 0 ? "AMD64" : "ARM64");
    if (policy != NULL && strcmp(policy, "pinned") == 0) {
        snprintf(key, sizeof(key), "AMI_ID_%s", suffix);
        value = config_get(cfg, key);
        if (value == NULL || value[0] == '\0') {
            return ENOENT;
        }
        snprintf(out, cap, "%s", value);
        return 0;
    }
    if (policy != NULL && strcmp(policy, "ssm") == 0) {
        char name[256];

        snprintf(key, sizeof(key), "AMI_SSM_%s", suffix);
        value = config_get(cfg, key);
        if (value == NULL || value[0] == '\0') {
            return ENOENT;
        }
        snprintf(name, sizeof(name), "%s", value);
        return ssm_fetch(config_project(cfg), region, name, out, cap);
    }
    {
        char name[512];

        snprintf(name, sizeof(name), "/%s/ami/baked/latest",
                 config_project(cfg));
        return ssm_fetch(config_project(cfg), region, name, out, cap);
    }
}

static int prod_ami_exists(void *ud, const char *region, const char *ami,
                           int *found) {
    aws_ctx *aws = NULL;
    ec2_client *client = NULL;
    ec2_image_list images = {0};
    const char *ids[1] = {ami};
    int rc;

    const struct prod_context *ctx = ud;

    rc = aws_init(&aws, ctx != NULL ? ctx->project : "default");
    if (rc != 0) {
        return rc;
    }
    rc = ec2_client_init(&client, aws, region);
    if (rc == 0) {
        rc = ec2_describe_images(client, ids, 1, &images);
    }
    if (rc == 0) {
        *found = images.count > 0;
    }
    ec2_image_list_free(&images);
    ec2_client_free(client);
    aws_free(aws);
    return rc;
}

static int manifest_key(const char *tag, char *out, size_t cap) {
    int rc = snprintf(out, cap, "releases/%s/release-manifest.txt", tag);

    return rc < 0 || (size_t)rc >= cap ? ENAMETOOLONG : 0;
}

static int prod_release_exists(void *ud, const char *bucket, const char *tag,
                               int *exists) {
    aws_ctx *aws = NULL;
    s3_client *client = NULL;
    char key[512];
    unsigned long long size = 0;
    char etag[S3_ETAG_MAX];
    int rc;

    const struct prod_context *ctx = ud;

    rc = manifest_key(tag, key, sizeof(key));
    if (rc != 0) {
        return rc;
    }
    rc = s3_open(ctx != NULL ? ctx->project : "default",
                 ctx != NULL ? ctx->region : "us-east-1", &aws, &client);
    if (rc != 0) {
        return rc;
    }
    rc = s3_head_object(client, bucket, key, &size, etag);
    s3_close(aws, client);
    if (rc == ENOENT) {
        *exists = 0;
        return 0;
    }
    if (rc != 0) {
        return rc;
    }
    *exists = 1;
    return 0;
}

/* Verify every manifest member by read-back; return the manifest sha. */
static int prod_verify_release(void *ud, const char *bucket, const char *tag,
                               char *sha_out, size_t cap) {
    aws_ctx *aws = NULL;
    s3_client *client = NULL;
    char key[512];
    char *manifest = NULL;
    size_t len = 0;
    int rc;

    const struct prod_context *ctx = ud;

    rc = manifest_key(tag, key, sizeof(key));
    if (rc != 0) {
        return rc;
    }
    rc = s3_open(ctx != NULL ? ctx->project : "default",
                 ctx != NULL ? ctx->region : "us-east-1", &aws, &client);
    if (rc != 0) {
        return rc;
    }
    rc = s3_get_object(client, bucket, key, &manifest, &len);
    if (rc == 0) {
        char digest[65];
        char *line = manifest;

        sha256_hex(manifest, len, digest);
        snprintf(sha_out, cap, "%s", digest);
        while (*line != '\0') {
            char *newline = strchr(line, '\n');
            char *sha = line;
            char *sep;
            char *name;
            char *payload = NULL;
            size_t payload_len = 0;
            char object_key[768];

            if (newline != NULL) {
                *newline = '\0';
            }
            while (*sha == ' ' || *sha == '\t') {
                sha++;
            }
            sep = strpbrk(sha, " \t");
            if (sep != NULL) {
                *sep++ = '\0';
                while (*sep == ' ' || *sep == '\t') {
                    sep++;
                }
                name = sep;
                {
                    size_t name_len = strlen(name);

                    while (name_len > 0 && (name[name_len - 1] == '\r' ||
                                            name[name_len - 1] == ' ')) {
                        name[--name_len] = '\0';
                    }
                }
                if (strlen(sha) != 64 || name[0] == '\0') {
                    rc = EBADMSG;
                } else if (snprintf(object_key, sizeof(object_key),
                                    "releases/%s/%s", tag, name) >=
                           (int)sizeof(object_key)) {
                    rc = ENAMETOOLONG;
                } else {
                    /* HEAD proves existence; GET verifies the member sha. */
                    unsigned long long size = 0;
                    char etag[S3_ETAG_MAX];

                    rc = s3_head_object(client, bucket, object_key, &size,
                                        etag);
                    if (rc == 0) {
                        rc = s3_get_object_sha256(client, bucket, object_key,
                                                  sha, &payload, &payload_len);
                    }
                    free(payload);
                }
            } else if (sha[0] != '\0') {
                rc = EBADMSG;
            }
            if (rc == EBADMSG || rc == ENOENT) {
                rc = CLI_EXIT_VERIFY;
            }
            if (rc != 0) {
                break;
            }
            if (newline == NULL) {
                break;
            }
            line = newline + 1;
        }
    }
    free(manifest);
    s3_close(aws, client);
    return rc;
}

static int upload_artifact(s3_client *client, const char *bucket,
                           const char *tag, const char *path,
                           buffer *manifest) {
    FILE *file;
    long size;
    char *data;
    char digest[65];
    char sidecar[65];
    char base[PATH_MAX];
    char object_key[768];
    char side_key[800];
    const char *slash;
    int rc;

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
    data = malloc((size_t)size + 1);
    if (data == NULL) {
        fclose(file);
        return ENOMEM;
    }
    if (fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        fclose(file);
        return EIO;
    }
    fclose(file);

    slash = strrchr(path, '/');
    snprintf(base, sizeof(base), "%s", slash != NULL ? slash + 1 : path);
    sha256_hex(data, (size_t)size, digest);
    snprintf(sidecar, sizeof(sidecar), "%s\n", digest);

    if (snprintf(object_key, sizeof(object_key), "releases/%s/%s", tag, base) >=
            (int)sizeof(object_key) ||
        snprintf(side_key, sizeof(side_key), "releases/%s/%s.sha256", tag,
                 base) >= (int)sizeof(side_key)) {
        free(data);
        return ENAMETOOLONG;
    }

    rc = s3_put_object(client, bucket, side_key, sidecar, strlen(sidecar),
                       "text/plain", NULL);
    if (rc == 0) {
        rc = s3_put_object(client, bucket, object_key, data, (size_t)size,
                           "application/octet-stream", NULL);
    }
    if (rc == 0) {
        char line[PATH_MAX + 80];

        if (deploy_manifest_line(digest, base, line, sizeof(line)) != 0) {
            rc = ENAMETOOLONG;
        } else {
            rc = buffer_append(manifest, line, strlen(line));
        }
    }
    free(data);
    return rc;
}

static int prod_publish_release(void *ud, const char *bucket, const char *tag,
                                const char *repo_root, const char *targets,
                                char *sha_out, size_t cap) {
    aws_ctx *aws = NULL;
    s3_client *client = NULL;
    buffer manifest = {0};
    char command[PATH_MAX * 4];
    char quoted_root[PATH_MAX * 2];
    char *paths = NULL;
    char *cursor;
    char prefix[512];
    s3_object_list existing = {0};
    int rc;

    const struct prod_context *ctx = ud;

    rc = s3_open(ctx != NULL ? ctx->project : "default",
                 ctx != NULL ? ctx->region : "us-east-1", &aws, &client);
    if (rc != 0) {
        return rc;
    }

    /* Wipe any manifest-less partial prefix for this tag first. */
    snprintf(prefix, sizeof(prefix), "releases/%s/", tag);
    if (s3_list_objects_v2(client, bucket, prefix, &existing) == 0) {
        for (size_t i = 0; i < existing.count; i++) {
            (void)s3_delete_object(client, bucket, existing.items[i].key);
        }
    }
    s3_object_list_free(&existing);

    if (deploy_shell_quote(repo_root, quoted_root, sizeof(quoted_root)) != 0) {
        s3_close(aws, client);
        return EINVAL;
    }
    rc = snprintf(command, sizeof(command), "cd %s && '%s' cquery --output=files %s",
                  quoted_root,
                  ctx != NULL && ctx->bazel != NULL ? ctx->bazel : "bazel",
                  targets);
    if (rc < 0 || (size_t)rc >= sizeof(command) ||
        run_capture(command, &paths) != 0) {
        s3_close(aws, client);
        return EIO;
    }
    cursor = paths;
    while (cursor != NULL && *cursor != '\0') {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');

        if (newline != NULL) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor = NULL;
        }
        if (line[0] != '\0') {
            rc = upload_artifact(client, bucket, tag, line, &manifest);
            if (rc != 0) {
                free(paths);
                free(manifest.data);
                s3_close(aws, client);
                return rc;
            }
        }
    }
    free(paths);

    {
        char manifest_key_name[512];
        char digest[65];

        if (manifest.data == NULL) {
            manifest.data = strdup("");
            if (manifest.data == NULL) {
                s3_close(aws, client);
                return ENOMEM;
            }
            manifest.len = 0;
        }
        sha256_hex(manifest.data, manifest.len, digest);
        snprintf(sha_out, cap, "%s", digest);
        snprintf(manifest_key_name, sizeof(manifest_key_name),
                 "releases/%s/release-manifest.txt", tag);
        rc = s3_put_object(client, bucket, manifest_key_name, manifest.data,
                           manifest.len, "text/plain", NULL);
    }
    free(manifest.data);
    s3_close(aws, client);
    return rc;
}


/* ------------------------------------------------------------------------- */
/* Production CFN vtable                                                     */
/* ------------------------------------------------------------------------- */

static int prod_aws_init(void *ud, const char *profile, aws_ctx **out) {
    (void)ud;
    return aws_init(out, profile);
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
                        int interval, int *timed_out) {
    (void)ud;
    return cfn_wait_for_change_set(client, region, stack, cs, attempts, interval,
                                   timed_out);
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

static int prod_read_template(void *ud, const char *repo_root, char **body_out) {
    char path[PATH_MAX];
    FILE *file;
    long size;
    char *body;
    int rc;

    (void)ud;
    rc = snprintf(path, sizeof(path), "%s/deploy/stackctl-infra.yaml",
                  repo_root);
    if (rc < 0 || (size_t)rc >= sizeof(path)) {
        return ENAMETOOLONG;
    }
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

static int prod_count_live(void *ud, const char *region, int *count) {
    const struct prod_context *ctx = ud;
    aws_ctx *aws = NULL;
    ec2_client *client = NULL;
    ec2_instance_list list = {0};
    const char *project_values[1];
    const char *state_values[2] = {"running", "pending"};
    ec2_filter filters[2];
    int rc;

    rc = aws_init(&aws, ctx != NULL ? ctx->project : "default");
    if (rc != 0) {
        return rc;
    }
    rc = ec2_client_init(&client, aws, region);
    if (rc != 0) {
        aws_free(aws);
        return rc;
    }
    project_values[0] = ctx != NULL ? ctx->project : "";
    filters[0].name = "tag:Project";
    filters[0].values = project_values;
    filters[0].value_count = 1;
    filters[1].name = "instance-state-name";
    filters[1].values = state_values;
    filters[1].value_count = 2;
    rc = ec2_describe_instances(client, filters, 2, &list);
    if (rc == 0) {
        *count = (int)list.count;
    }
    ec2_instance_list_free(&list);
    ec2_client_free(client);
    aws_free(aws);
    return rc;
}

static deploy_release_entry *find_entry(deploy_release_entry *entries,
                                        size_t *count, const char *tag) {
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(entries[i].tag, tag) == 0) {
            return &entries[i];
        }
    }
    if (*count >= 256) {
        return NULL;
    }
    deploy_release_entry *entry = &entries[*count];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->tag, sizeof(entry->tag), "%s", tag);
    (*count)++;
    return entry;
}

static int prod_prune(void *ud, const char *bucket, const char *pinned,
                      const char *previous, const char *just_uploaded) {
    const struct prod_context *ctx = ud;
    aws_ctx *aws = NULL;
    s3_client *client = NULL;
    s3_object_list listing = {0};
    deploy_release_entry entries[256] = {0};
    size_t entry_count = 0;
    long long now = (long long)time(NULL);
    int rc;

    rc = s3_open(ctx != NULL ? ctx->project : "default",
                 ctx != NULL ? ctx->region : "us-east-1", &aws, &client);
    if (rc != 0) {
        return rc;
    }
    rc = s3_list_objects_v2(client, bucket, "releases/", &listing);
    if (rc != 0) {
        s3_close(aws, client);
        return rc;
    }
    for (size_t i = 0; i < listing.count; i++) {
        const char *key = listing.items[i].key;
        const char *tag_start;
        const char *slash;
        char tag[128];
        size_t tag_len;
        long long stamp = 0;
        deploy_release_entry *entry;

        if (key == NULL || strncmp(key, "releases/", 9) != 0) {
            continue;
        }
        tag_start = key + 9;
        slash = strchr(tag_start, '/');
        if (slash == NULL) {
            continue;
        }
        tag_len = (size_t)(slash - tag_start);
        if (tag_len == 0 || tag_len >= sizeof(tag)) {
            continue;
        }
        memcpy(tag, tag_start, tag_len);
        tag[tag_len] = '\0';
        if (!tag_is_semver(tag)) {
            continue;
        }
        entry = find_entry(entries, &entry_count, tag);
        if (entry == NULL) {
            continue;
        }
        if (deploy_iso8601_to_epoch(listing.items[i].last_modified, &stamp) ==
                0 &&
            stamp > entry->newest_epoch) {
            entry->newest_epoch = stamp;
        }
        if (strcmp(slash + 1, "release-manifest.txt") == 0) {
            if (deploy_iso8601_to_epoch(listing.items[i].last_modified,
                                        &stamp) == 0) {
                entry->manifest_epoch = stamp;
            }
        }
    }
    s3_object_list_free(&listing);

    (void)deploy_prune_mark(entries, entry_count, pinned, previous,
                            just_uploaded, now);

    rc = 0;
    for (size_t i = 0; i < entry_count; i++) {
        char prefix[256];
        s3_object_list prefix_list = {0};

        if (entries[i].delete_me == 0) {
            continue;
        }
        if (snprintf(prefix, sizeof(prefix), "releases/%s/", entries[i].tag) >=
            (int)sizeof(prefix)) {
            continue;
        }
        if (s3_list_objects_v2(client, bucket, prefix, &prefix_list) == 0) {
            for (size_t j = 0; j < prefix_list.count; j++) {
                if (s3_delete_object(client, bucket,
                                     prefix_list.items[j].key) != 0) {
                    rc = EIO;
                }
            }
        } else {
            rc = EIO;
        }
        s3_object_list_free(&prefix_list);
    }
    s3_close(aws, client);
    return rc;
}

static const deploy_ops complete_ops = {
    .git_provenance = prod_provenance,
    .freshness = prod_freshness,
    .resolve_bucket = prod_bucket,
    .resolve_ami = prod_resolve_ami,
    .ami_exists = prod_ami_exists,
    .release_exists = prod_release_exists,
    .verify_release = prod_verify_release,
    .publish_release = prod_publish_release,
    .count_live_instances = prod_count_live,
    .prune_releases = prod_prune,
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
    .read_template = prod_read_template,
};

/* ------------------------------------------------------------------------- */
/* Reporting                                                                 */
/* ------------------------------------------------------------------------- */

typedef void (*deploy_param_diff_emit)(void *ud, const char *name,
                                       const char *old_value,
                                       const char *new_value);

static const cfn_parameter *find_param(const cfn_parameter *params,
                                       size_t count, const char *key) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(params[i].key, key) == 0) {
            return &params[i];
        }
    }
    return NULL;
}

/*
 * Walk the planned parameter set against the current stack. New parameters are
 * "Added", parameters present in both with different values are "Changed", and
 * current parameters missing from the plan are "Removed". Unchanged parameters
 * are skipped. `emit` may be NULL to count only.
 */
static size_t param_diff_each(const cfn_stack *current,
                              const cfn_parameter *params, size_t param_count,
                              deploy_param_diff_emit emit, void *ud) {
    size_t count = 0;

    for (size_t i = 0; i < param_count; i++) {
        const char *old_value =
            current != NULL ? cfn_stack_parameter(current, params[i].key)
                            : NULL;

        if (old_value == NULL) {
            if (emit != NULL) {
                emit(ud, params[i].key, NULL, params[i].value);
            }
            count++;
        } else if (strcmp(old_value, params[i].value) != 0) {
            if (emit != NULL) {
                emit(ud, params[i].key, old_value, params[i].value);
            }
            count++;
        }
    }
    if (current != NULL) {
        for (size_t i = 0; i < current->parameter_count; i++) {
            const cfn_parameter *old = &current->parameters[i];

            if (find_param(params, param_count, old->key) == NULL) {
                if (emit != NULL) {
                    emit(ud, old->key, old->value, NULL);
                }
                count++;
            }
        }
    }
    return count;
}

static void emit_param_diff_human(void *ud, const char *name,
                                  const char *old_value,
                                  const char *new_value) {
    FILE *out = ud;

    if (old_value == NULL) {
        fprintf(out, "  %s: Added = %s\n", name, new_value);
    } else if (new_value == NULL) {
        fprintf(out, "  %s: Removed = %s\n", name, old_value);
    } else {
        fprintf(out, "  %s: Changed: %s -> %s\n", name, old_value, new_value);
    }
}

size_t deploy_param_diff_write(FILE *out, const cfn_stack *current,
                               const cfn_parameter *params,
                               size_t param_count) {
    size_t count;

    if (out == NULL) {
        return 0;
    }
    count = param_diff_each(current, params, param_count, NULL, NULL);
    if (count == 0) {
        return 0;
    }
    fprintf(out, "parameter changes:\n");
    (void)param_diff_each(current, params, param_count, emit_param_diff_human,
                          out);
    return count;
}

typedef struct param_diff_json {
    yyjson_mut_doc *doc;
    yyjson_mut_val *array;
} param_diff_json;

static void emit_param_diff_json(void *ud, const char *name,
                                 const char *old_value,
                                 const char *new_value) {
    param_diff_json *ctx = ud;
    yyjson_mut_val *entry = yyjson_mut_obj(ctx->doc);

    yyjson_mut_obj_add_str(ctx->doc, entry, "name", name);
    yyjson_mut_obj_add_str(ctx->doc, entry, "action",
                           old_value == NULL ? "Added"
                           : new_value == NULL ? "Removed"
                                               : "Changed");
    if (old_value != NULL) {
        yyjson_mut_obj_add_str(ctx->doc, entry, "old", old_value);
    } else {
        yyjson_mut_obj_add_null(ctx->doc, entry, "old");
    }
    if (new_value != NULL) {
        yyjson_mut_obj_add_str(ctx->doc, entry, "new", new_value);
    } else {
        yyjson_mut_obj_add_null(ctx->doc, entry, "new");
    }
    yyjson_mut_arr_append(ctx->array, entry);
}

static void report_json(const deploy_env *env, const char *stack, size_t changes,
                        int executed, const char *status,
                        const cfn_stack *current, const cfn_parameter *params,
                        size_t param_count) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root;
    param_diff_json diff_ctx;

    if (doc == NULL) {
        return;
    }
    root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "verb", "deploy");
    yyjson_mut_obj_add_str(doc, root, "stack", stack);
    yyjson_mut_obj_add_str(doc, root, "tag", env->tag);
    yyjson_mut_obj_add_str(doc, root, "manifest_sha256", env->manifest_sha);
    yyjson_mut_obj_add_uint(doc, root, "changes", changes);
    yyjson_mut_obj_add_bool(doc, root, "executed", executed != 0);
    yyjson_mut_obj_add_bool(doc, root, "dry_run", env->dry_run != 0);
    yyjson_mut_obj_add_str(doc, root, "status", status);
    diff_ctx.doc = doc;
    diff_ctx.array = yyjson_mut_arr(doc);
    (void)param_diff_each(current, params, param_count, emit_param_diff_json,
                          &diff_ctx);
    yyjson_mut_obj_add_val(doc, root, "parameter_diff", diff_ctx.array);
    (void)cli_json_write(env->out != NULL ? env->out : stdout, doc);
    yyjson_mut_doc_free(doc);
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

static int deploy_run_impl(deploy_env *env) {
    const deploy_ops *ops;
    void *ud;
    struct prod_context prod_ctx = {0};
    const char *project;
    const char *region;
    const char *targets;
    char repo_root[PATH_MAX];
    char *allocated_root = NULL;
    char *template_body = NULL;
    const char *template_source = "";
    char bucket[256];
    char stack[CFN_STACK_NAME_MAX];
    char change_set_name[CFN_CHANGE_SET_NAME_MAX];
    char ami_ids[2][64] = {{0}};
    char ami_arches[2][8] = {{0}};
    size_t ami_count = 0;
    const char *const *arches;
    int rollback;
    int exists = 0;
    aws_ctx *aws = NULL;
    cfn_client *client = NULL;
    cfn_stack_list stacks = {0};
    cfn_change_set_type type = CFN_CHANGE_SET_TYPE_CREATE;
    int prior_review = 0;
    cfn_parameter params[12] = {0};
    size_t param_count = 0;
    cfn_change_set_spec spec = {0};
    cfn_change_set_result result = {0};
    cfn_change_set change_set = {0};
    char prior_pinned[128] = {0};
    int live_count = 0;
    const cfn_stack *current_stack = NULL;
    int timed_out = 0;
    int rc;

    if (env == NULL || env->cfg == NULL || env->config_dir == NULL) {
        return CLI_EXIT_USAGE;
    }
    ops = env->ops != NULL ? env->ops : test_ops;
    ud = env->ops_ud != NULL ? env->ops_ud : test_ops_ud;
    if (ops == NULL) {
        ops = &complete_ops;
        prod_ctx.project = config_project(env->cfg);
        prod_ctx.region = config_region(env->cfg);
        prod_ctx.bazel = config_get(env->cfg, "BAZEL_COMMAND");
        ud = &prod_ctx;
    }
    if (ops->git_provenance == NULL || ops->resolve_bucket == NULL ||
        ops->create_change_set == NULL) {
        return CLI_EXIT_USAGE;
    }

    project = config_project(env->cfg);
    region = config_region(env->cfg);
    targets = config_get(env->cfg, "RELEASE_TARGETS");
    snprintf(stack, sizeof(stack), "%s-infra", project);
    snprintf(change_set_name, sizeof(change_set_name), "%s-infra-deploy",
             project);
    rollback = env->tag_arg != NULL && env->tag_arg[0] != '\0';

    rc = config_repo_root(env->config_dir, &allocated_root);
    if (rc == 0) {
        snprintf(repo_root, sizeof(repo_root), "%s", allocated_root);
        free(allocated_root);
    } else {
        const char *bwd = config_build_working_directory();

        snprintf(repo_root, sizeof(repo_root), "%s", bwd != NULL ? bwd : ".");
    }

    if (ops->read_template != NULL) {
        rc = ops->read_template(ud, repo_root, &template_body);
        if (rc != 0) {
            fprintf(env->err, "stackctl: cannot read the infra template\n");
            return CLI_EXIT_USAGE;
        }
        template_source = template_body;
    }

    if (rollback) {
        if (!tag_is_semver(env->tag_arg)) {
            fprintf(env->err, "stackctl: invalid release tag %s\n",
                    env->tag_arg);
            return CLI_EXIT_USAGE;
        }
        snprintf(env->tag, sizeof(env->tag), "%s", env->tag_arg);
    } else {
        rc = ops->git_provenance(ud, repo_root, env->allow_dirty, env->tag,
                                 sizeof(env->tag));
        if (rc != 0) {
            if (rc == CLI_EXIT_USAGE) {
                fprintf(env->err,
                        "stackctl: ambiguous release identity (more than one "
                        "vX.Y.Z tag on HEAD)\n");
            } else {
                fprintf(env->err,
                        "stackctl: provenance gate failed (annotated vX.Y.Z "
                        "tag on HEAD and origin)\n");
            }
            return rc;
        }
        if (!tag_is_semver(env->tag)) {
            fprintf(env->err, "stackctl: HEAD has no vX.Y.Z release tag\n");
            return CLI_EXIT_VERIFY;
        }
        if (env->skip_build == 0) {
            rc = ops->freshness(ud, repo_root, targets);
            if (rc != 0) {
                fprintf(env->err,
                        "stackctl: freshness gate failed: deployment artifact "
                        "stale or unbuilt\n");
                return rc;
            }
        }
    }

    rc = ops->resolve_bucket(ud, project, region, bucket, sizeof(bucket));
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot resolve the artifact bucket\n");
        return CLI_EXIT_AWS;
    }

    /* AMI-region preflight before any publish or stack mutation. */
    arches = config_arch_list(env->cfg);
    for (size_t i = 0; arches != NULL && arches[i] != NULL; i++) {
        int found = 0;

        if (ami_count >= 2) {
            break;
        }
        rc = ops->resolve_ami(ud, env->cfg, region, arches[i], ami_ids[ami_count],
                              sizeof(ami_ids[ami_count]));
        if (rc != 0) {
            fprintf(env->err,
                    "stackctl: cannot resolve the %s AMI in %s\n", arches[i],
                    region);
            return CLI_EXIT_USAGE;
        }
        rc = ops->ami_exists(ud, region, ami_ids[ami_count], &found);
        if (rc != 0) {
            fprintf(env->err, "stackctl: cannot verify the %s AMI in %s\n",
                    arches[i], region);
            return CLI_EXIT_AWS;
        }
        if (found == 0) {
            fprintf(env->err,
                    "stackctl: AMI %s for %s does not resolve in %s\n",
                    ami_ids[ami_count], arches[i], region);
            return CLI_EXIT_USAGE;
        }
        snprintf(ami_arches[ami_count], sizeof(ami_arches[ami_count]), "%s",
                 arches[i]);
        ami_count++;
    }

    rc = ops->release_exists(ud, bucket, env->tag, &exists);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot check releases/%s/\n", env->tag);
        return CLI_EXIT_AWS;
    }
    if (exists != 0) {
        if (env->skip_build != 0 && !rollback) {
            fprintf(env->err,
                    "stackctl: tag %s is immutable; cut a new tag (--skip-build "
                    "does not override tag immutability)\n",
                    env->tag);
            return CLI_EXIT_VERIFY;
        }
        rc = ops->verify_release(ud, bucket, env->tag, env->manifest_sha,
                                 sizeof(env->manifest_sha));
        if (rc != 0) {
            fprintf(env->err,
                    "stackctl: release %s failed manifest verification\n",
                    env->tag);
            return rc == CLI_EXIT_VERIFY ? CLI_EXIT_VERIFY : CLI_EXIT_AWS;
        }
    } else if (rollback) {
        fprintf(env->err,
                "stackctl: release %s no longer exists (pruned); available "
                "releases are listed by `stackctl status`\n",
                env->tag);
        return CLI_EXIT_VERIFY;
    } else {
        rc = ops->publish_release(ud, bucket, env->tag, repo_root, targets,
                                  env->manifest_sha,
                                  sizeof(env->manifest_sha));
        if (rc != 0) {
            fprintf(env->err, "stackctl: publishing release %s failed\n",
                    env->tag);
            return CLI_EXIT_AWS;
        }
        /* Read back every member and the manifest before recording it. */
        {
            char readback_sha[65];

            rc = ops->verify_release(ud, bucket, env->tag, readback_sha,
                                     sizeof(readback_sha));
        }
        if (rc != 0) {
            fprintf(env->err,
                    "stackctl: published release %s failed read-back "
                    "verification\n",
                    env->tag);
            return rc == CLI_EXIT_VERIFY ? CLI_EXIT_VERIFY : CLI_EXIT_AWS;
        }
    }

    rc = ops->aws_init(ud, project, &aws);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot authenticate as %s\n", project);
        return CLI_EXIT_AWS;
    }
    rc = ops->cfn_create(ud, aws, &client);
    if (rc != 0) {
        ops->aws_free(ud, aws);
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
                    "stackctl: another operation is in progress on %s\n",
                    stack);
            rc = CLI_EXIT_AWS;
            goto done;
        }
        if (status_is_healthy(status)) {
            type = CFN_CHANGE_SET_TYPE_UPDATE;
        } else if (status == CFN_STACK_STATUS_REVIEW_IN_PROGRESS) {
            type = CFN_CHANGE_SET_TYPE_CREATE;
            prior_review = 1;
        } else {
            fprintf(env->err, "stackctl: %s is in %s; refusing to proceed\n",
                    stack, cfn_stack_status_string(status));
            rc = CLI_EXIT_AWS;
            goto done;
        }
        {
            const char *pinned =
                cfn_stack_tag(&stacks.items[0], "stackctl:release-tag");

            if (pinned != NULL) {
                snprintf(prior_pinned, sizeof(prior_pinned), "%s", pinned);
            }
        }
    }
    current_stack = stacks.count > 0 ? &stacks.items[0] : NULL;

    if (ops->count_live_instances != NULL) {
        int counted = 0;

        if (ops->count_live_instances(ud, region, &counted) == 0) {
            live_count = counted;
        }
    }

    add_param(params, &param_count, "ProjectName", project);
    add_param(params, &param_count, "ReleaseTag", env->tag);
    add_param(params, &param_count, "ReleaseManifestSha256", env->manifest_sha);
    add_param(params, &param_count, "AmiPolicy",
              config_get(env->cfg, "AMI_POLICY"));
    for (size_t i = 0; i < ami_count; i++) {
        char key[32];

        if (make_camel_arch(ami_arches[i], key, sizeof(key)) == 0) {
            add_param(params, &param_count, key, ami_ids[i]);
        }
    }
    add_param(params, &param_count, "OperatorCidr",
              config_get(env->cfg, "OPERATOR_CIDR"));
    add_param(params, &param_count, "IngressTcp",
              config_get(env->cfg, "INGRESS_TCP"));
    add_param(params, &param_count, "IngressUdp",
              config_get(env->cfg, "INGRESS_UDP"));
    {
        const char *buckets = config_get(env->cfg, "BUCKET_MODULES");

        add_param(params, &param_count, "CertBucketEnabled",
                  buckets != NULL && strstr(buckets, "cert") != NULL ? "true"
                                                                     : "false");
    }
    add_param(params, &param_count, "EnableImageBuilder",
              config_get(env->cfg, "ENABLE_IMAGE_BUILDER"));

    spec.stack_name = stack;
    spec.change_set_name = change_set_name;
    spec.template_body = template_source;
    spec.type = type;
    spec.parameters = params;
    spec.parameter_count = param_count;
    spec.description = "stackctl deploy";
    spec.capabilities = 0;

    rc = ops->create_change_set(ud, client, region, &spec, &result);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot create the change set for %s\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }
    rc = ops->wait_change_set(ud, client, region, stack, change_set_name, 120,
                              5, &timed_out);
    if (rc != 0 || timed_out != 0) {
        fprintf(env->err, "stackctl: change set for %s did not complete\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
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
            report_json(env, stack, 0, 0, "unchanged", current_stack, params,
                        param_count);
        } else {
            fprintf(env->out, "%s: no changes (release %s recorded)\n", stack,
                    env->tag);
        }
        rc = CLI_EXIT_OK;
        goto done;
    }

    if (env->json == 0) {
        fprintf(env->out,
                "release: %s; template/config from current checkout "
                "(dirty: %s)\n",
                env->tag, env->allow_dirty != 0 ? "yes" : "no");
        fprintf(env->out, "%s: %zu change(s) in the change set\n", stack,
                change_set.change_count);
        (void)deploy_param_diff_write(env->out, current_stack, params,
                                      param_count);
        fprintf(env->out, "live Project instances: %d\n", live_count);
        if (live_count > 0) {
            fprintf(env->out,
                    "warning: %d live instance(s) may be disrupted by this "
                    "change; review the change set before applying\n",
                    live_count);
        }
    }

    if (env->dry_run != 0) {
        (void)ops->delete_change_set(ud, client, region, stack,
                                     change_set_name);
        if (prior_review != 0) {
            (void)ops->delete_stack(ud, client, region, stack);
        }
        if (env->json != 0) {
            report_json(env, stack, change_set.change_count, 0, "dry-run",
                        current_stack, params, param_count);
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
                report_json(env, stack, change_set.change_count, 0, "aborted",
                        current_stack, params, param_count);
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
        fprintf(env->err, "stackctl: stack operation on %s did not complete\n",
                stack);
        rc = CLI_EXIT_AWS;
        goto done;
    }
    env->executed = 1;

    /* Step 5: prune old releases. A prune failure never fails the deploy. */
    if (ops->prune_releases != NULL) {
        rc = ops->prune_releases(ud, bucket,
                                 prior_pinned[0] != '\0' ? prior_pinned : NULL,
                                 env->previous_tag[0] != '\0'
                                     ? env->previous_tag
                                     : NULL,
                                 env->tag);
        if (rc != 0) {
            fprintf(env->err,
                    "stackctl: warning: release pruning was incomplete\n");
        }
        rc = CLI_EXIT_OK;
    }

    if (env->json != 0) {
        report_json(env, stack, change_set.change_count, 1, "deployed",
                        current_stack, params, param_count);
    } else {
        fprintf(env->out, "%s: deployed release %s\n", stack, env->tag);
    }
    rc = CLI_EXIT_OK;

done:
    free(template_body);
    ops->change_set_free(ud, &change_set);
    ops->stack_list_free(ud, &stacks);
    ops->cfn_destroy(ud, client);
    ops->aws_free(ud, aws);
    return rc;
}

int deploy_run(deploy_env *env) { return deploy_run_impl(env); }

/* ------------------------------------------------------------------------- */
/* Public entry point                                                        */
/* ------------------------------------------------------------------------- */

static int derive_config_dir(char *out, size_t cap) {
    const char *base = config_build_working_directory();
    char candidate[PATH_MAX];
    char *real;
    int rc;

    if (base == NULL || base[0] == '\0') {
        base = ".";
    }
    rc = snprintf(candidate, sizeof(candidate), "%s/deploy/aws", base);
    if (rc < 0 || (size_t)rc >= sizeof(candidate)) {
        return ENAMETOOLONG;
    }
    if (access(candidate, F_OK) != 0) {
        snprintf(candidate, sizeof(candidate), "%s", base);
    }
    real = realpath(candidate, NULL);
    if (real == NULL) {
        return errno != 0 ? errno : ENOENT;
    }
    snprintf(out, cap, "%s", real);
    free(real);
    return 0;
}

static int confirm_with_ctx(void *ud, const char *prompt) {
    return cli_confirm((cli_ctx *)ud, prompt);
}

/*
 * Read the tag recorded immediately before this run from the release-history
 * file (`<timestamp>\t<tag>` lines). A fresh state dir yields no tag.
 */
static void last_release_tag(state_store *store, char *out, size_t cap) {
    const char *path;
    FILE *file;
    char line[256];

    out[0] = '\0';
    if (store == NULL) {
        return;
    }
    path = state_release_history_path(store);
    if (path == NULL) {
        return;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *tab = strchr(line, '\t');
        char *tag;
        char *end;

        if (tab == NULL) {
            continue;
        }
        tag = tab + 1;
        end = tag + strlen(tag);
        while (end > tag && (end[-1] == '\n' || end[-1] == '\r')) {
            *--end = '\0';
        }
        if (tag[0] != '\0') {
            snprintf(out, cap, "%s", tag);
        }
    }
    fclose(file);
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
        snprintf(args, sizeof(args), "deploy");
    }
    snprintf(outcome, sizeof(outcome), "%s",
             code == CLI_EXIT_OK ? "success" : "failure");
    (void)state_operations_log_append(store, "deploy", args, outcome);
}

int cli_cmd_deploy(cli_ctx *ctx) {
    static const cli_option_spec specs[] = {
        {"tag", 0, 1, 0, "<vX.Y.Z>", "deploy/roll back an existing release tag"},
        {"allow-dirty", 0, 0, 0, NULL, "allow a dirty working tree"},
        {"skip-build", 0, 0, 0, NULL, "skip the freshness gate"},
    };
    cli_args args = {0};
    deploy_env env = {0};
    char config_dir[PATH_MAX];
    int rc;

    if (ctx == NULL) {
        return cli_fail(NULL, CLI_EXIT_USAGE, "deploy: no context");
    }
    rc = cli_ctx_parse_args(ctx, specs, sizeof(specs) / sizeof(specs[0]),
                            &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "deploy: invalid arguments");
    }
    if (args.positional_count != 0) {
        cli_args_free(&args);
        return cli_fail(ctx, CLI_EXIT_USAGE,
                        "deploy does not take positional arguments");
    }
    env.tag_arg = cli_args_value(&args, "tag");
    env.allow_dirty = cli_args_flag(&args, "allow-dirty");
    env.skip_build = cli_args_flag(&args, "skip-build");
    /* Keep the tag pointer valid until after deploy_run(). */
    rc = derive_config_dir(config_dir, sizeof(config_dir));
    if (rc != 0) {
        cli_args_free(&args);
        return cli_fail(ctx, CLI_EXIT_USAGE,
                        "deploy: cannot locate the project config directory");
    }

    env.cfg = cli_ctx_config(ctx);
    env.config_dir = config_dir;
    env.yes = cli_ctx_yes(ctx);
    env.dry_run = cli_ctx_dry_run(ctx);
    env.json = cli_ctx_json(ctx);
    env.out = stdout;
    env.err = stderr;
    env.ops = NULL;
    env.ops_ud = NULL;
    env.confirm = confirm_with_ctx;
    env.confirm_ud = ctx;
    last_release_tag(cli_ctx_state(ctx), env.previous_tag,
                     sizeof(env.previous_tag));

    rc = deploy_run(&env);
    if (rc == CLI_EXIT_OK && env.dry_run == 0 && env.tag[0] != '\0') {
        state_store *store = cli_ctx_state(ctx);

        if (store != NULL) {
            (void)state_release_history_append(store, env.tag);
        }
    }
    cli_args_free(&args);
    log_outcome(ctx, rc);
    return rc;
}
