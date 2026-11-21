/*
 * refresh_ami_test.c — public-behaviour tests for `stackctl refresh-ami`.
 *
 * Drives the real `cli_cmd_refresh_ami` entry point against a temporary
 * project directory. The SSM resolver is injected (no network, no credentials);
 * the file layer is the production realpath+rename implementation exercised on
 * real temp files, including a symlinked `.env`.
 */

#include "refresh_ami.h"
#include "refresh_ami_internal.h"

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

static void mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t len;

    if (path == NULL) {
        return;
    }
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

static char *write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    fputs(text, file);
    fclose(file);
    return (char *)path;
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
    if (size < 0) {
        fclose(file);
        return NULL;
    }
    rewind(file);
    buffer = calloc((size_t)size + 1, 1);
    if (buffer != NULL && fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        buffer = NULL;
    }
    fclose(file);
    return buffer;
}

/* Rewrite the single occurrence of `from` in `path` to `to`. */
static int replace_in_file(const char *path, const char *from, const char *to) {
    char *text = read_text(path);
    char *pos;
    size_t prefix;
    size_t need;
    char *rewritten;

    if (text == NULL) {
        return 0;
    }
    pos = strstr(text, from);
    if (pos == NULL) {
        free(text);
        return 0;
    }
    prefix = (size_t)(pos - text);
    need = prefix + strlen(to) + strlen(pos + strlen(from)) + 1;
    rewritten = calloc(need, 1);
    if (rewritten != NULL) {
        snprintf(rewritten, need, "%.*s%s%s", (int)prefix, text, to,
                 pos + strlen(from));
        write_text(path, rewritten);
    }
    free(rewritten);
    free(text);
    return rewritten != NULL; /* pointer value only; not dereferenced */
}

/* ------------------------------------------------------------------------- */
/* Fake SSM resolver                                                         */
/* ------------------------------------------------------------------------- */

typedef struct fake_ssm {
    const char *amd64;
    const char *arm64;
    int calls;
    int identity_calls;
    int identity_rc;
    char last_name[256];
} fake_ssm;

static int fake_resolve(void *ud, const char *profile, const char *region,
                        const char *name, char **value_out) {
    fake_ssm *fake = ud;
    const char *value;

    (void)profile;
    (void)region;
    fake->calls++;
    snprintf(fake->last_name, sizeof(fake->last_name), "%s", name);
    if (strstr(name, "amd64") != NULL || strstr(name, "AMD64") != NULL) {
        value = fake->amd64;
    } else if (strstr(name, "arm64") != NULL ||
               strstr(name, "ARM64") != NULL) {
        value = fake->arm64;
    } else {
        value = NULL;
    }
    if (value == NULL) {
        return ENOENT;
    }
    *value_out = strdup(value);
    return *value_out != NULL ? 0 : ENOMEM;
}

static int fake_assert_identity(void *ud, const char *profile) {
    fake_ssm *fake = ud;

    (void)profile;
    fake->identity_calls++;
    return fake->identity_rc;
}

static const refresh_ami_ops fake_ops = {.resolve_parameter = fake_resolve,
                                         .assert_identity = fake_assert_identity};
/* File seam that fails the committed example write but never the local .env. */
typedef struct failing_file_ops {
    int writes;
    char failed_path[PATH_MAX];
} failing_file_ops;

static int fake_write_fail_example(void *ud, const char *path,
                                   const char *data, size_t len) {
    failing_file_ops *fake = ud;
    FILE *file;

    fake->writes++;
    if (strstr(path, ".env.example") != NULL) {
        snprintf(fake->failed_path, sizeof(fake->failed_path), "%s", path);
        return EIO;
    }
    file = fopen(path, "w");
    if (file == NULL) {
        return EIO;
    }
    if (fwrite(data, 1, len, file) != len) {
        fclose(file);
        return EIO;
    }
    fclose(file);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Project fixture                                                           */
/* ------------------------------------------------------------------------- */

typedef struct fixture {
    char root[PATH_MAX];
    char config_dir[PATH_MAX];
    char state_dir[PATH_MAX];
    char env_path[PATH_MAX];
    char example_path[PATH_MAX];
    char variant_path[PATH_MAX];
    char variant_example_path[PATH_MAX];
    int region_variant;
    const char *policy;
    int include_ssm_keys;
    int include_pin_in_example;
} fixture;

static const char *base_keys =
    "PROJECT=demo\n"
    "ARCH=amd64\n"
    "SPOT_DEFAULT=false\n"
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
    "ENABLE_CI_USER=true\n";

static void fixture_init(fixture *fx, int region_variant, const char *policy,
                         int include_ssm_keys, int include_pin) {
    char template[] = "/tmp/stackctl-refresh-XXXXXX";
    char *root = mkdtemp(template);
    FILE *file;

    memset(fx, 0, sizeof(*fx));
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof(fx->root), "%s", root);

    snprintf(fx->config_dir, sizeof(fx->config_dir), "%s/deploy/aws", fx->root);
    mkdir_p(fx->config_dir);
    snprintf(fx->state_dir, sizeof(fx->state_dir), "%s/state", fx->root);
    mkdir_p(fx->state_dir);

    {
        char marker[PATH_MAX];
        snprintf(marker, sizeof(marker), "%s/MODULE.bazel", fx->root);
        write_text(marker, "");
    }

    fx->region_variant = region_variant;
    fx->policy = policy;
    fx->include_ssm_keys = include_ssm_keys;
    fx->include_pin_in_example = include_pin;

    snprintf(fx->env_path, sizeof(fx->env_path), "%s/.env", fx->config_dir);
    snprintf(fx->example_path, sizeof(fx->example_path), "%s/.env.example",
             fx->config_dir);
    snprintf(fx->variant_path, sizeof(fx->variant_path), "%s/.env.eu-west-1",
             fx->config_dir);
    snprintf(fx->variant_example_path, sizeof(fx->variant_example_path),
             "%s/.env.eu-west-1.example", fx->config_dir);

    const char *local_path = region_variant ? fx->variant_path : fx->env_path;
    const char *example = region_variant ? fx->variant_example_path
                                         : fx->example_path;

    file = fopen(local_path, "w");
    if (file == NULL) {
        perror(local_path);
        exit(1);
    }
    fputs(base_keys, file);
    fprintf(file, "REGION=%s\n", region_variant ? "eu-west-1" : "us-east-1");
    fprintf(file, "AMI_POLICY=%s\n", policy);
    if (strcmp(policy, "pinned") == 0) {
        fputs("AMI_ID_AMD64=ami-oldamd64\n", file);
    }
    if (include_ssm_keys) {
        fputs("AMI_SSM_AMD64=/aws/service/ami/amd64\n", file);
    }
    fclose(file);

    file = fopen(example, "w");
    if (file == NULL) {
        perror(example);
        exit(1);
    }
    fputs(base_keys, file);
    fprintf(file, "REGION=%s\n", region_variant ? "eu-west-1" : "us-east-1");
    fprintf(file, "AMI_POLICY=%s\n", policy);
    if (include_pin) {
        fputs("AMI_ID_AMD64=ami-oldamd64\n", file);
    }
    if (include_ssm_keys) {
        fputs("AMI_SSM_AMD64=/aws/service/ami/amd64\n", file);
    }
    fclose(file);
}

static void fixture_setenv(const fixture *fx) {
    if (setenv("XDG_STATE_HOME", fx->state_dir, 1) != 0 ||
        setenv("BUILD_WORKING_DIRECTORY", fx->root, 1) != 0) {
        perror("setenv");
        exit(1);
    }
}

static void fixture_clear_env(void) {
    unsetenv("XDG_STATE_HOME");
    unsetenv("BUILD_WORKING_DIRECTORY");
}

static cli_ctx *make_ctx(const fixture *fx, const char *extra) {
    char *argv[8];
    int argc = 0;
    cli_ctx *ctx = NULL;

    argv[argc++] = "stackctl";
    argv[argc++] = "--project";
    argv[argc++] = (char *)fx->config_dir;
    if (fx->region_variant) {
        argv[argc++] = "--region";
        argv[argc++] = "eu-west-1";
    }
    argv[argc++] = "refresh-ami";
    if (extra != NULL) {
        argv[argc++] = (char *)extra;
    }
    argv[argc] = NULL;

    if (cli_ctx_init(argc, argv, &ctx) != 0) {
        return NULL;
    }
    return ctx;
}

/* ------------------------------------------------------------------------- */
/* Cases                                                                     */
/* ------------------------------------------------------------------------- */

static void test_null_context(void) {
    CHECK(cli_cmd_refresh_ami(NULL) == CLI_EXIT_USAGE, "NULL ctx is usage");
}

static void test_rejects_bad_flag(void) {
    fixture fx;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    {
        cli_ctx *ctx = make_ctx(&fx, "--not-a-real-flag");
        CHECK(ctx != NULL, "ctx built before verb argument parsing");
        if (ctx != NULL) {
            CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_USAGE,
                  "unknown verb flag rejected by the verb");
            cli_ctx_free(ctx);
        }
    }
    fixture_clear_env();
}

static void test_requires_pinned_policy(void) {
    fixture fx;
    cli_ctx *ctx;

    fixture_init(&fx, 0, "ssm", 1, 0);
    fixture_setenv(&fx);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx for ssm project");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_USAGE,
          "ssm policy is a hard error");
    cli_ctx_free(ctx);
    fixture_clear_env();
}

static void test_missing_ssm_key(void) {
    fixture fx;
    cli_ctx *ctx;

    fixture_init(&fx, 0, "pinned", 0, 1);
    fixture_setenv(&fx);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx without AMI_SSM_AMD64");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_USAGE,
          "missing AMI_SSM_* is usage");
    cli_ctx_free(ctx);
    fixture_clear_env();
}

static void test_dual_write(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    char *local;
    char *example;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);

    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx for dual write");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK, "dual write succeeds");
    CHECK(fake.calls == 1, "one parameter resolved");
    CHECK(strcmp(fake.last_name, "/aws/service/ami/amd64") == 0,
          "resolved the declared arch parameter");

    local = read_text(fx.env_path);
    example = read_text(fx.example_path);
    CHECK(local != NULL && strstr(local, "AMI_ID_AMD64=ami-newamd64") != NULL,
          "local .env updated");
    CHECK(example != NULL &&
              strstr(example, "AMI_ID_AMD64=ami-newamd64") != NULL,
          ".env.example updated");
    CHECK(local != NULL && strstr(local, "AMI_POLICY=pinned") != NULL,
          "unrelated keys preserved");
    free(local);
    free(example);

    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_idempotent_second_run(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx run 1");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK, "first run ok");
    cli_ctx_free(ctx);

    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx run 2");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK, "second run is idempotent");
    cli_ctx_free(ctx);

    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_missing_key_in_example(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};

    fixture_init(&fx, 0, "pinned", 1, 0);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx missing example pin");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_USAGE,
          "missing example key is usage");
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_dry_run_writes_nothing(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    char *before;
    char *after;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    before = read_text(fx.env_path);
    ctx = make_ctx(&fx, "--dry-run");
    CHECK(ctx != NULL, "ctx dry-run");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK, "dry-run succeeds");
    after = read_text(fx.env_path);
    CHECK(before != NULL && after != NULL && strcmp(before, after) == 0,
          "dry-run leaves files untouched");
    free(before);
    free(after);
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_symlink_preserved(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    char real_path[PATH_MAX];
    struct stat info;

    fixture_init(&fx, 0, "pinned", 1, 1);
    snprintf(real_path, sizeof(real_path), "%s/real.env", fx.config_dir);
    (void)rename(fx.env_path, real_path);
    CHECK(symlink("real.env", fx.env_path) == 0, "create .env symlink");
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx symlink");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK, "symlinked .env updated");
    CHECK(lstat(fx.env_path, &info) == 0 && S_ISLNK(info.st_mode),
          "symlink is preserved");
    {
        char *real = read_text(real_path);
        CHECK(real != NULL && strstr(real, "ami-newamd64") != NULL,
              "symlink target updated");
        free(real);
    }
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_region_variant_targets(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    char *variant;
    char *example;

    fixture_init(&fx, 1, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx region variant");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK, "region variant refreshed");
    variant = read_text(fx.variant_path);
    example = read_text(fx.variant_example_path);
    CHECK(variant != NULL && strstr(variant, "ami-newamd64") != NULL,
          "variant .env updated");
    CHECK(example != NULL && strstr(example, "ami-newamd64") != NULL,
          "variant example updated");
    free(variant);
    free(example);
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_ssm_failure_maps_to_aws(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = NULL};

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx ssm failure");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_USAGE,
          "ENOENT parameter maps to usage");
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

static void test_dual_write_example_failure_leaves_local(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    failing_file_ops file_ops = {0};
    refresh_ami_file_ops ops = {.write_atomic = fake_write_fail_example};
    char *before;
    char *after;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &fake);
    refresh_ami_set_file_ops_for_test(&ops, &file_ops);
    before = read_text(fx.env_path);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx for failing example write");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_USAGE,
          "example write failure is reported");
    after = read_text(fx.env_path);
    CHECK(file_ops.writes >= 1, "example write attempted");
    CHECK(strstr(file_ops.failed_path, ".env.example") != NULL,
          "the failing target was the example");
    CHECK(before != NULL && after != NULL && strcmp(before, after) == 0,
          "local .env untouched when .env.example fails");
    free(before);
    free(after);
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    refresh_ami_set_file_ops_for_test(NULL, NULL);
    fixture_clear_env();
}

/*
 * A --project outside the conventional `<repo>/deploy/aws` must drive the
 * dual-write: discovery follows config_dir(), never a re-guessed path. The
 * decoy BUILD_WORKING_DIRECTORY has no deploy/aws, so the old heuristic would
 * have failed to find any config at all.
 */
static void test_project_dir_follows_accessor(void) {
    char root_template[] = "/tmp/stackctl-refresh-custom-XXXXXX";
    char *root = mkdtemp(root_template);
    char config_dir[PATH_MAX];
    char decoy[PATH_MAX];
    char marker[PATH_MAX];
    char env_path[PATH_MAX];
    char example_path[PATH_MAX];
    char state_dir[PATH_MAX];
    char text[4096];
    cli_ctx *ctx = NULL;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    char *argv[6];
    char *example;

    CHECK(root != NULL, "custom project temp root");
    if (root == NULL) {
        return;
    }
    snprintf(config_dir, sizeof config_dir, "%s/custom/aws", root);
    snprintf(decoy, sizeof decoy, "%s/decoy", root);
    snprintf(state_dir, sizeof state_dir, "%s/state", root);
    snprintf(marker, sizeof marker, "%s/MODULE.bazel", root);
    snprintf(env_path, sizeof env_path, "%s/.env", config_dir);
    snprintf(example_path, sizeof example_path, "%s/.env.example", config_dir);

    mkdir_p(config_dir);
    mkdir_p(decoy);
    mkdir_p(state_dir);
    write_text(marker, "");

    snprintf(text, sizeof text,
             "%sREGION=us-east-1\nAMI_POLICY=pinned\n"
             "AMI_ID_AMD64=ami-oldamd64\nAMI_SSM_AMD64=/aws/service/ami/amd64\n",
             base_keys);
    write_text(env_path, text);
    snprintf(text, sizeof text,
             "%sREGION=us-east-1\nAMI_POLICY=pinned\n"
             "AMI_ID_AMD64=ami-oldamd64\nAMI_SSM_AMD64=/aws/service/ami/amd64\n",
             base_keys);
    write_text(example_path, text);

    CHECK(setenv("XDG_STATE_HOME", state_dir, 1) == 0, "custom state home");
    CHECK(setenv("BUILD_WORKING_DIRECTORY", decoy, 1) == 0, "decoy build cwd");
    refresh_ami_set_ops_for_test(&fake_ops, &fake);

    argv[0] = "stackctl";
    argv[1] = "--project";
    argv[2] = config_dir;
    argv[3] = "refresh-ami";
    argv[4] = NULL;
    CHECK(cli_ctx_init(4, argv, &ctx) == 0, "ctx for custom --project");
    if (ctx != NULL) {
        CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK,
              "refresh-ami honours the --project config directory");
        example = read_text(example_path);
        CHECK(example != NULL && strstr(example, "ami-newamd64") != NULL,
              ".env.example written next to the actual config dir");
        free(example);
        cli_ctx_free(ctx);
    }

    refresh_ami_set_ops_for_test(NULL, NULL);
    unsetenv("BUILD_WORKING_DIRECTORY");
    unsetenv("XDG_STATE_HOME");
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
    rc = refresh_ami_prod_aws_init_for_test("prod-abort", &aws);
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

static void test_identity_guard_before_ssm(void) {
    fixture fx;
    cli_ctx *ctx;
    fake_ssm mismatch = {.amd64 = "ami-newamd64",
                         .identity_rc = CLI_EXIT_VERIFY};

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    refresh_ami_set_ops_for_test(&fake_ops, &mismatch);
    ctx = make_ctx(&fx, NULL);
    CHECK(ctx != NULL, "ctx for identity mismatch");
    CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_VERIFY,
          "identity mismatch exits 3");
    CHECK(mismatch.identity_calls == 1, "identity asserted once");
    CHECK(mismatch.calls == 0, "no SSM read before identity");
    cli_ctx_free(ctx);
    refresh_ami_set_ops_for_test(NULL, NULL);
    fixture_clear_env();

    {
        fake_ssm matching = {.amd64 = "ami-newamd64"};

        fixture_init(&fx, 0, "pinned", 1, 1);
        fixture_setenv(&fx);
        refresh_ami_set_ops_for_test(&fake_ops, &matching);
        ctx = make_ctx(&fx, NULL);
        CHECK(ctx != NULL, "ctx for matching identity");
        CHECK(cli_cmd_refresh_ami(ctx) == CLI_EXIT_OK,
              "matching identity proceeds");
        CHECK(matching.identity_calls == 1, "identity asserted once");
        CHECK(matching.calls == 1, "SSM read follows identity");
        cli_ctx_free(ctx);
        refresh_ami_set_ops_for_test(NULL, NULL);
        fixture_clear_env();
    }
}

/*
 * F19: drive refresh_ami_run directly with a tmpfile stdout so the dry-run
 * diff can be asserted without touching process-wide file descriptors.
 */
static char *run_dry_run_capture(const fixture *fx, fake_ssm *fake, int *rc_out) {
    cli_ctx *ctx = make_ctx(fx, NULL);
    refresh_ami_env env = {0};
    FILE *sink = tmpfile();
    char *text = NULL;

    if (ctx == NULL || sink == NULL) {
        if (ctx != NULL) {
            cli_ctx_free(ctx);
        }
        if (sink != NULL) {
            fclose(sink);
        }
        *rc_out = CLI_EXIT_USAGE;
        return NULL;
    }
    env.cfg = cli_ctx_config(ctx);
    env.profile = config_project(env.cfg);
    env.config_dir = config_dir(env.cfg);
    env.region = config_region(env.cfg);
    env.dry_run = 1;
    env.json = 0;
    env.out = sink;
    env.err = stderr;
    env.ops = &fake_ops;
    env.ops_ud = fake;
    *rc_out = refresh_ami_run(&env);

    {
        long size = -1;

        if (fseek(sink, 0, SEEK_END) == 0) {
            size = ftell(sink);
        }
        if (size >= 0 && fseek(sink, 0, SEEK_SET) == 0) {
            text = calloc((size_t)size + 1, 1);
            if (text != NULL &&
                fread(text, 1, (size_t)size, sink) != (size_t)size) {
                free(text);
                text = NULL;
            }
        }
    }
    fclose(sink);
    cli_ctx_free(ctx);
    return text;
}

/* Rewrite both fixture files as ARCH=both with the arm64 pins present. */
static void fixture_set_both_arches(fixture *fx) {
    const char *paths[2];
    char *texts[2];

    paths[0] = fx->env_path;
    paths[1] = fx->example_path;
    for (size_t i = 0; i < 2; i++) {
        char *pos;
        size_t prefix_len;
        const char *rest;
        size_t need;
        char *rewritten;

        texts[i] = read_text(paths[i]);
        CHECK(texts[i] != NULL, "both-arch fixture readable");
        if (texts[i] == NULL) {
            return;
        }
        pos = strstr(texts[i], "ARCH=amd64\n");
        CHECK(pos != NULL, "both-arch fixture has base ARCH line");
        if (pos == NULL) {
            free(texts[i]);
            return;
        }
        prefix_len = (size_t)(pos - texts[i]);
        rest = pos + strlen("ARCH=amd64\n");
        need = prefix_len + strlen("ARCH=both\n") + strlen(rest) +
               strlen("INSTANCE_TYPES_ARM64=g5g.xlarge\n"
                      "AMI_ID_ARM64=ami-oldarm64\n"
                      "AMI_SSM_ARM64=/aws/service/ami/arm64\n") +
               1;
        rewritten = calloc(need, 1);
        CHECK(rewritten != NULL, "both-arch rewrite buffer");
        if (rewritten == NULL) {
            free(texts[i]);
            return;
        }
        snprintf(rewritten, need,
                 "%.*sARCH=both\n%sINSTANCE_TYPES_ARM64=g5g.xlarge\n"
                 "AMI_ID_ARM64=ami-oldarm64\n"
                 "AMI_SSM_ARM64=/aws/service/ami/arm64\n",
                 (int)prefix_len, texts[i], rest);
        write_text(paths[i], rewritten);
        free(rewritten);
        free(texts[i]);
    }
}

static void test_dry_run_diff_changed_key(void) {
    fixture fx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    int rc = -1;
    char *out = NULL;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    out = run_dry_run_capture(&fx, &fake, &rc);
    CHECK(rc == CLI_EXIT_OK, "dry-run diff succeeds");
    CHECK(out != NULL && strstr(out, "AMI_ID_AMD64: ami-oldamd64 -> ami-newamd64\n") != NULL,
          "changed key prints exactly one old -> new line");
    free(out);
    fixture_clear_env();
}

/* F19: when the active .env already holds the new value but the committed
 * example still holds an older one, the diff reports the example's old value
 * so the dual-file update is visible. */
static void test_dry_run_diff_uses_example_old_value(void) {
    fixture fx;
    fake_ssm fake = {.amd64 = "ami-newamd64"};
    int rc = -1;
    char *out = NULL;

    fixture_init(&fx, 0, "pinned", 1, 1);
    CHECK(replace_in_file(fx.env_path, "AMI_ID_AMD64=ami-oldamd64",
                          "AMI_ID_AMD64=ami-newamd64"),
          "active .env rewritten to the new value");
    fixture_setenv(&fx);
    out = run_dry_run_capture(&fx, &fake, &rc);
    CHECK(rc == CLI_EXIT_OK, "example-only dry-run diff succeeds");
    CHECK(out != NULL &&
              strstr(out,
                     "AMI_ID_AMD64: ami-oldamd64 -> ami-newamd64\n") != NULL,
          "diff uses the example-file old value when .env is unchanged");
    free(out);
    fixture_clear_env();
}

static void test_dry_run_diff_unchanged_key_silent(void) {
    fixture fx;
    fake_ssm fake = {.amd64 = "ami-oldamd64"};
    int rc = -1;
    char *out = NULL;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_setenv(&fx);
    out = run_dry_run_capture(&fx, &fake, &rc);
    CHECK(rc == CLI_EXIT_OK, "unchanged dry-run succeeds");
    CHECK(out != NULL && strstr(out, "AMI_ID_AMD64") == NULL,
          "unchanged key is silent");
    free(out);
    fixture_clear_env();
}

static void test_dry_run_diff_multiple_keys_ordered(void) {
    fixture fx;
    fake_ssm fake = {.amd64 = "ami-newamd64", .arm64 = "ami-newarm64"};
    int rc = -1;
    char *out = NULL;
    const char *amd64_line;
    const char *arm64_line;

    fixture_init(&fx, 0, "pinned", 1, 1);
    fixture_set_both_arches(&fx);
    fixture_setenv(&fx);
    out = run_dry_run_capture(&fx, &fake, &rc);
    CHECK(rc == CLI_EXIT_OK, "multi-arch dry-run succeeds");
    amd64_line = out != NULL
                     ? strstr(out, "AMI_ID_AMD64: ami-oldamd64 -> ami-newamd64\n")
                     : NULL;
    arm64_line = out != NULL
                     ? strstr(out, "AMI_ID_ARM64: ami-oldarm64 -> ami-newarm64\n")
                     : NULL;
    CHECK(amd64_line != NULL, "amd64 diff line present");
    CHECK(arm64_line != NULL, "arm64 diff line present");
    CHECK(amd64_line != NULL && arm64_line != NULL && amd64_line < arm64_line,
          "diff lines follow declared arch order");
    free(out);
    fixture_clear_env();
}

int main(void) {
    test_prod_aws_init_installs_abort_hook();
    test_null_context();
    test_rejects_bad_flag();
    test_requires_pinned_policy();
    test_missing_ssm_key();
    test_dual_write();
    test_idempotent_second_run();
    test_missing_key_in_example();
    test_dual_write_example_failure_leaves_local();
    test_dry_run_writes_nothing();
    test_symlink_preserved();
    test_region_variant_targets();
    test_ssm_failure_maps_to_aws();
    test_project_dir_follows_accessor();
    test_identity_guard_before_ssm();
    test_dry_run_diff_changed_key();
    test_dry_run_diff_uses_example_old_value();
    test_dry_run_diff_unchanged_key_silent();
    test_dry_run_diff_multiple_keys_ordered();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("refresh_ami_test: ok\n");
    return 0;
}
