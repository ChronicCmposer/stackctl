/*
 * refresh_ami.c — `stackctl refresh-ami` (spec §4 refresh-ami).
 *
 * Resolves each declared arch's AMI SSM float and dual-writes the resulting
 * pin into the local `.env` and its committed `.env.example` counterpart. The
 * write is an in-place replacement of the matching `KEY=` line only, via a
 * same-directory temp file + rename(2) over the target's realpath, so a
 * symlinked `.env` is updated rather than replaced.
 */

#include "refresh_ami_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aws.h"
#include "ssm.h"
#include "yyjson.h"

/* ------------------------------------------------------------------------- */
/* Test seams                                                                */
/* ------------------------------------------------------------------------- */

static const refresh_ami_ops *test_ops;
static void *test_ops_ud;
static const refresh_ami_file_ops *test_file_ops;
static void *test_file_ud;

void refresh_ami_set_ops_for_test(const refresh_ami_ops *ops, void *ud) {
    test_ops = ops;
    test_ops_ud = ud;
}

void refresh_ami_set_file_ops_for_test(const refresh_ami_file_ops *ops,
                                       void *ud) {
    test_file_ops = ops;
    test_file_ud = ud;
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
        size_t cap = buf->cap != 0 ? buf->cap : 256;
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

static int default_read_file(void *ud, const char *path, char **data_out,
                             size_t *len_out) {
    FILE *file;
    char *data;
    long size;

    (void)ud;
    file = fopen(path, "rb");
    if (file == NULL) {
        return errno != 0 ? errno : EIO;
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
    data[size] = '\0';
    fclose(file);
    *data_out = data;
    *len_out = (size_t)size;
    return 0;
}

/*
 * Replace `path` with `data` atomically. The target's real path is resolved
 * first so a symlink is followed (the link itself is preserved); the temp file
 * is created in the real file's directory and renamed over it.
 */
static int default_write_atomic(void *ud, const char *path, const char *data,
                                size_t len) {
    char *real;
    char *dir;
    char temp[PATH_MAX];
    int fd = -1;
    size_t written = 0;
    int rc = 0;

    (void)ud;
    real = realpath(path, NULL);
    if (real == NULL) {
        return errno != 0 ? errno : ENOENT;
    }
    dir = strdup(real);
    if (dir == NULL) {
        free(real);
        return ENOMEM;
    }
    {
        char *slash = strrchr(dir, '/');

        if (slash == NULL) {
            free(dir);
            free(real);
            return EINVAL;
        }
        *slash = '\0';
    }
    if (snprintf(temp, sizeof(temp), "%s/.stackctl-tmp-XXXXXX", dir) >=
        (int)sizeof(temp)) {
        free(dir);
        free(real);
        return ENAMETOOLONG;
    }
    fd = mkstemp(temp);
    if (fd < 0) {
        rc = errno != 0 ? errno : EIO;
        free(dir);
        free(real);
        return rc;
    }
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);

        if (n < 0) {
            rc = errno != 0 ? errno : EIO;
            break;
        }
        written += (size_t)n;
    }
    if (rc == 0 && fsync(fd) != 0) {
        rc = errno != 0 ? errno : EIO;
    }
    if (close(fd) != 0 && rc == 0) {
        rc = errno != 0 ? errno : EIO;
    }
    if (rc == 0 && rename(temp, real) != 0) {
        rc = errno != 0 ? errno : EIO;
    }
    if (rc != 0) {
        (void)unlink(temp);
    }
    free(dir);
    free(real);
    return rc;
}

static int read_file(const refresh_ami_env *env, const char *path,
                     char **data_out, size_t *len_out) {
    const refresh_ami_file_ops *ops = env->file_ops != NULL
                                          ? env->file_ops
                                          : test_file_ops;
    if (ops != NULL && ops->read_file != NULL) {
        return ops->read_file(env->file_ud != NULL ? env->file_ud : test_file_ud,
                              path, data_out, len_out);
    }
    return default_read_file(NULL, path, data_out, len_out);
}

static int write_atomic(const refresh_ami_env *env, const char *path,
                        const char *data, size_t len) {
    const refresh_ami_file_ops *ops = env->file_ops != NULL
                                          ? env->file_ops
                                          : test_file_ops;
    if (ops != NULL && ops->write_atomic != NULL) {
        return ops->write_atomic(
            env->file_ud != NULL ? env->file_ud : test_file_ud, path, data,
            len);
    }
    return default_write_atomic(NULL, path, data, len);
}

/* `amd64` -> `AMI_ID_AMD64`. */
static int make_arch_key(const char *prefix, const char *arch, char *out,
                         size_t cap) {
    size_t used;
    int rc = snprintf(out, cap, "%s", prefix);

    if (rc < 0 || (size_t)rc >= cap) {
        return ENAMETOOLONG;
    }
    used = (size_t)rc;
    for (const char *p = arch; *p != '\0'; p++) {
        if (used + 1 >= cap) {
            return ENAMETOOLONG;
        }
        out[used++] = (char)(*p >= 'a' && *p <= 'z' ? *p - 'a' + 'A' : *p);
    }
    out[used] = '\0';
    return 0;
}

/*
 * Return the value of a `KEY=...` line (leading whitespace tolerated) or NULL.
 * The replacement operates on whole lines; this helper is used for diffs.
 */
static const char *find_line_value(const char *text, const char *key,
                                   char *value, size_t cap) {
    size_t key_len = strlen(key);
    const char *line = text;

    while (line != NULL && *line != '\0') {
        const char *end = strchr(line, '\n');
        const char *cursor = line;
        size_t line_len = end != NULL ? (size_t)(end - line) : strlen(line);

        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        if ((size_t)((line + line_len) - cursor) > key_len &&
            strncmp(cursor, key, key_len) == 0) {
            const char *after = cursor + key_len;

            while (*after == ' ' || *after == '\t') {
                after++;
            }
            if (*after == '=') {
                const char *value_start = after + 1;
                size_t value_len;

                value_start += strspn(value_start, " \t");
                value_len = (size_t)((line + line_len) - value_start);
                while (value_len > 0 &&
                       (value_start[value_len - 1] == ' ' ||
                        value_start[value_len - 1] == '\t')) {
                    value_len--;
                }
                if (value_len >= cap) {
                    value_len = cap - 1;
                }
                memcpy(value, value_start, value_len);
                value[value_len] = '\0';
                return value;
            }
        }
        line = end != NULL ? end + 1 : NULL;
    }
    return NULL;
}

/*
 * Rewrite one KEY= line in `text`, preserving every other byte. Returns a
 * heap buffer via *out; a missing key is ENOENT (never appended).
 */
static int replace_key_line(const char *text, const char *key,
                            const char *value, char **out) {
    size_t key_len = strlen(key);
    const char *line = text;
    buffer result = {0};
    int rc = 0;

    while (*line != '\0') {
        const char *end = strchr(line, '\n');
        size_t line_len = end != NULL ? (size_t)(end - line) : strlen(line);
        const char *cursor = line;
        int matched = 0;

        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        if ((size_t)((line + line_len) - cursor) > key_len &&
            strncmp(cursor, key, key_len) == 0) {
            const char *after = cursor + key_len;

            while (*after == ' ' || *after == '\t') {
                after++;
            }
            matched = *after == '=';
        }
        if (matched) {
            rc = buffer_append(&result, key, key_len);
            if (rc == 0) {
                rc = buffer_append(&result, "=", 1);
            }
            if (rc == 0) {
                rc = buffer_append(&result, value, strlen(value));
            }
            if (rc == 0) {
                rc = buffer_append(&result, "\n", 1);
            }
            if (rc != 0) {
                free(result.data);
                return rc;
            }
        } else {
            rc = buffer_append(&result, line, line_len);
            if (rc == 0 && end != NULL) {
                rc = buffer_append(&result, "\n", 1);
            }
            if (rc != 0) {
                free(result.data);
                return rc;
            }
        }
        line = end != NULL ? end + 1 : line + line_len;
    }
    if (result.data == NULL) {
        return ENOENT;
    }
    *out = result.data;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Production SSM resolver                                                   */
/* ------------------------------------------------------------------------- */

static int production_resolve(void *ud, const char *profile, const char *region,
                              const char *name, char **value_out) {
    aws_ctx *aws = NULL;
    ssm_client *client = NULL;
    ssm_parameter parameter = {0};
    int rc;

    (void)ud;
    rc = aws_init(&aws, profile);
    if (rc != 0) {
        return rc;
    }
    rc = ssm_client_init(&client, aws, region);
    if (rc != 0) {
        aws_free(aws);
        return rc;
    }
    rc = ssm_get_parameter(client, name, 0, &parameter);
    if (rc == 0) {
        *value_out = parameter.value != NULL ? strdup(parameter.value) : NULL;
        if (*value_out == NULL) {
            rc = ENOMEM;
        }
    }
    ssm_parameter_free(&parameter);
    ssm_client_free(client);
    aws_free(aws);
    return rc;
}

static const refresh_ami_ops production_ops = {
    .resolve_parameter = production_resolve,
};

/* ------------------------------------------------------------------------- */
/* Paths and reporting                                                       */
/* ------------------------------------------------------------------------- */

static int is_regular(const char *path) {
    struct stat info;

    return stat(path, &info) == 0 && S_ISREG(info.st_mode);
}

static int target_paths(const refresh_ami_env *env, char *local, size_t local_cap,
                        char *example, size_t example_cap) {
    char variant[PATH_MAX];
    char variant_example[PATH_MAX];
    int rc;

    rc = snprintf(variant, sizeof(variant), "%s/.env.%s", env->config_dir,
                  env->region);
    if (rc < 0 || (size_t)rc >= sizeof(variant)) {
        return ENAMETOOLONG;
    }
    if (is_regular(variant)) {
        rc = snprintf(variant_example, sizeof(variant_example),
                      "%s/.env.%s.example", env->config_dir, env->region);
        if (rc < 0 || (size_t)rc >= sizeof(variant_example)) {
            return ENAMETOOLONG;
        }
        snprintf(local, local_cap, "%s", variant);
        snprintf(example, example_cap, "%s", variant_example);
        return 0;
    }
    snprintf(local, local_cap, "%s/.env", env->config_dir);
    snprintf(example, example_cap, "%s/.env.example", env->config_dir);
    return 0;
}

static void report_json(const refresh_ami_env *env, const char *local,
                        const char *example, int write_ok) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);

    if (doc == NULL) {
        return;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_val *files = yyjson_mut_arr(doc);

    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_str(doc, root, "verb", "refresh-ami");
    yyjson_mut_obj_add_bool(doc, root, "dry_run", env->dry_run != 0);
    if (write_ok != 0) {
        yyjson_mut_arr_add_str(doc, files, local);
        yyjson_mut_arr_add_str(doc, files, example);
        yyjson_mut_obj_add_val(doc, root, "files", files);
    }
    yyjson_mut_obj_add_str(doc, root, "message", "run deploy to apply");
    (void)cli_json_write(env->out != NULL ? env->out : stdout, doc);
    yyjson_mut_doc_free(doc);
}

/* ------------------------------------------------------------------------- */
/* Verb body                                                                 */
/* ------------------------------------------------------------------------- */

typedef struct pin {
    char ssm_key[64];
    char pin_key[64];
    char *value;
} pin;

int refresh_ami_run(const refresh_ami_env *env) {
    const refresh_ami_ops *ops;
    void *ops_ud;
    const char *const *arches;
    pin pins[2] = {0};
    size_t pin_count = 0;
    char local[PATH_MAX];
    char example[PATH_MAX];
    char *local_text = NULL;
    char *example_text = NULL;
    char *example_original = NULL;
    size_t local_len = 0;
    size_t example_len = 0;
    size_t example_original_len = 0;
    int rc;

    if (env == NULL || env->cfg == NULL || env->config_dir == NULL ||
        env->region == NULL) {
        return CLI_EXIT_USAGE;
    }
    ops = env->ops != NULL ? env->ops : test_ops;
    ops_ud = env->ops_ud != NULL ? env->ops_ud : test_ops_ud;
    if (ops == NULL || ops->resolve_parameter == NULL) {
        ops = &production_ops;
        ops_ud = NULL;
    }
    if (strcmp(config_get(env->cfg, "AMI_POLICY"), "pinned") != 0) {
        fprintf(env->err, "stackctl: refresh-ami requires AMI_POLICY=pinned; "
                          "ssm/baked-policy projects track their AMI at launch\n");
        return CLI_EXIT_USAGE;
    }

    arches = config_arch_list(env->cfg);
    for (size_t i = 0; arches != NULL && arches[i] != NULL; i++) {
        const char *ssm_name;

        if (pin_count >= sizeof(pins) / sizeof(pins[0])) {
            return CLI_EXIT_USAGE;
        }
        if (make_arch_key("AMI_SSM_", arches[i], pins[pin_count].ssm_key,
                          sizeof(pins[pin_count].ssm_key)) != 0 ||
            make_arch_key("AMI_ID_", arches[i], pins[pin_count].pin_key,
                          sizeof(pins[pin_count].pin_key)) != 0) {
            return CLI_EXIT_USAGE;
        }
        ssm_name = config_get(env->cfg, pins[pin_count].ssm_key);
        if (ssm_name == NULL || ssm_name[0] == '\0') {
            fprintf(env->err,
                    "stackctl: missing %s (required by refresh-ami)\n",
                    pins[pin_count].ssm_key);
            return CLI_EXIT_USAGE;
        }
        rc = ops->resolve_parameter(ops_ud, env->profile, env->region, ssm_name,
                                    &pins[pin_count].value);
        if (rc != 0) {
            fprintf(env->err, "stackctl: cannot resolve %s: %s\n", ssm_name,
                    rc == ENOENT ? "parameter not found" : "AWS error");
            return rc == ENOENT ? CLI_EXIT_USAGE : CLI_EXIT_AWS;
        }
        pin_count++;
    }
    if (pin_count == 0) {
        fprintf(env->err, "stackctl: ARCH declares no architectures\n");
        return CLI_EXIT_USAGE;
    }

    if (target_paths(env, local, sizeof(local), example, sizeof(example)) != 0) {
        return CLI_EXIT_USAGE;
    }

    rc = read_file(env, local, &local_text, &local_len);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot read %s\n", local);
        return CLI_EXIT_USAGE;
    }
    rc = read_file(env, example, &example_text, &example_len);
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot read %s\n", example);
        free(local_text);
        return CLI_EXIT_USAGE;
    }

    /* Both files must contain every pin key before anything is written. */
    for (size_t i = 0; i < pin_count; i++) {
        char ignored[64];

        if (find_line_value(local_text, pins[i].pin_key, ignored,
                            sizeof(ignored)) == NULL) {
            fprintf(env->err, "stackctl: %s is missing %s\n", local,
                    pins[i].pin_key);
            rc = CLI_EXIT_USAGE;
            goto done;
        }
        if (find_line_value(example_text, pins[i].pin_key, ignored,
                            sizeof(ignored)) == NULL) {
            fprintf(env->err, "stackctl: %s is missing %s\n", example,
                    pins[i].pin_key);
            rc = CLI_EXIT_USAGE;
            goto done;
        }
    }

    example_original = strdup(example_text);
    example_original_len = example_len;
    if (example_original == NULL) {
        rc = CLI_EXIT_USAGE;
        goto done;
    }

    for (size_t i = 0; i < pin_count; i++) {
        char *updated_local = NULL;
        char *updated_example = NULL;

        rc = replace_key_line(local_text, pins[i].pin_key, pins[i].value,
                              &updated_local);
        if (rc == 0) {
            free(local_text);
            local_text = updated_local;
            local_len = strlen(local_text);
        }
        if (rc != 0) {
            fprintf(env->err, "stackctl: cannot update %s\n", local);
            rc = CLI_EXIT_USAGE;
            goto done;
        }
        rc = replace_key_line(example_text, pins[i].pin_key, pins[i].value,
                              &updated_example);
        if (rc == 0) {
            free(example_text);
            example_text = updated_example;
            example_len = strlen(example_text);
        }
        if (rc != 0) {
            fprintf(env->err, "stackctl: cannot update %s\n", example);
            rc = CLI_EXIT_USAGE;
            goto done;
        }
    }

    if (env->dry_run != 0) {
        if (env->json != 0) {
            report_json(env, local, example, 0);
        } else {
            fprintf(env->out, "would update %s and %s\n", local, example);
            for (size_t i = 0; i < pin_count; i++) {
                fprintf(env->out, "  %s=%s\n", pins[i].pin_key, pins[i].value);
            }
            fprintf(env->out, "run deploy to apply\n");
        }
        rc = CLI_EXIT_OK;
        goto done;
    }

    /*
     * Write the committed example first: if it fails, the local .env is left
     * untouched (no half-applied dual write).
     */
    rc = write_atomic(env, example, example_text, example_len);
    if (rc == 0) {
        rc = write_atomic(env, local, local_text, local_len);
        if (rc != 0) {
            /* Roll the example back so the pair never diverges. */
            if (write_atomic(env, example, example_original,
                             example_original_len) != 0) {
                fprintf(env->err,
                        "stackctl: cannot restore %s after a failed dual "
                        "write; cleanup incomplete\n",
                        example);
                rc = CLI_EXIT_CLEANUP;
                goto done;
            }
        }
    }
    if (rc != 0) {
        fprintf(env->err, "stackctl: cannot write refresh-ami targets\n");
        rc = CLI_EXIT_USAGE;
        goto done;
    }

    if (env->json != 0) {
        report_json(env, local, example, 1);
    } else {
        for (size_t i = 0; i < pin_count; i++) {
            fprintf(env->out, "updated %s=%s in %s and %s\n", pins[i].pin_key,
                    pins[i].value, local, example);
        }
        fprintf(env->out, "run deploy to apply\n");
    }
    rc = CLI_EXIT_OK;

done:
    for (size_t i = 0; i < pin_count; i++) {
        free(pins[i].value);
    }
    free(local_text);
    free(example_text);
    free(example_original);
    return rc;
}

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
    if (!is_regular(candidate) && access(candidate, F_OK) != 0) {
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
        snprintf(args, sizeof(args), "refresh-ami");
    }
    snprintf(outcome, sizeof(outcome), "%s",
             code == CLI_EXIT_OK ? "success" : "failure");
    (void)state_operations_log_append(store, "refresh-ami", args, outcome);
}

int cli_cmd_refresh_ami(cli_ctx *ctx) {
    static const cli_option_spec specs[] = {
        {NULL, 0, 0, 0, NULL, NULL},
    };
    cli_args args = {0};
    refresh_ami_env env = {0};
    char config_dir[PATH_MAX];
    int rc;

    if (ctx == NULL) {
        return cli_fail(NULL, CLI_EXIT_USAGE, "refresh-ami: no context");
    }
    rc = cli_ctx_parse_args(ctx, specs, 0, &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "refresh-ami: invalid arguments");
    }
    if (args.positional_count != 0) {
        cli_args_free(&args);
        return cli_fail(ctx, CLI_EXIT_USAGE,
                        "refresh-ami does not take positional arguments");
    }
    cli_args_free(&args);

    rc = derive_config_dir(config_dir, sizeof(config_dir));
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE,
                        "refresh-ami: cannot locate the project config "
                        "directory");
    }

    env.cfg = cli_ctx_config(ctx);
    env.profile = config_project(env.cfg);
    env.config_dir = config_dir;
    env.region = config_region(env.cfg);
    env.dry_run = cli_ctx_dry_run(ctx);
    env.json = cli_ctx_json(ctx);
    env.out = stdout;
    env.err = stderr;
    env.ops = NULL;
    env.ops_ud = NULL;

    rc = refresh_ami_run(&env);
    log_outcome(ctx, rc);
    return rc;
}
