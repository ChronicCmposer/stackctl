/*
 * config_test.c — validation table tests for core/config (spec §3).
 *
 * Builds throwaway repo roots under /tmp with a MODULE.bazel marker and a
 * deploy/aws/.env, then exercises the fail-closed validation contract. No
 * external test framework; the process exits non-zero on any failed check.
 */

#include "config.h"
#include "envfile.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

typedef struct {
    const char *key;
    const char *value; /* NULL removes a base key */
} kv;

static const kv base[] = {
    {"PROJECT", "demo"},
    {"REGION", "us-east-1"},
    {"ARCH", "amd64"},
    {"SPOT_DEFAULT", "false"},
    {"AMI_POLICY", "pinned"},
    {"AMI_ID_AMD64", "ami-0123456789abcdef0"},
    {"INSTANCE_TYPES_AMD64", "g4dn.xlarge"},
    {"ROOT_VOLUME_SIZE", "100"},
    {"KEY_NAME", "demo-key"},
    {"SSH_IDENTITY", "/home/operator/.ssh/demo"},
    {"BUCKET_MODULES", "artifact,cert"},
    {"ENABLE_IMAGE_BUILDER", "false"},
    {"SETUP_ENTRYPOINT", "deploy.sh"},
    {"SSH_PORT", "22"},
    {"OPERATOR_CIDR", "203.0.113.0/24"},
    {"INGRESS_TCP", "443"},
    {"INGRESS_UDP", ""},
    {"RELEASE_TARGETS", "//app:deploy.tar.gz"},
    {"RELEASE_PREFIXES", "releases/"},
};

/* ------------------------------------------------------------------------- */
/* Filesystem + stdout helpers                                               */
/* ------------------------------------------------------------------------- */

static char *make_temp_root(void) {
    char template[] = "/tmp/stackctl-config-XXXXXX";
    char *root = mkdtemp(template);

    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    return strdup(root);
}

static char *join_path(const char *dir, const char *name) {
    size_t need = strlen(dir) + strlen(name) + 2;
    char *path = malloc(need);

    if (path == NULL) {
        perror("malloc");
        exit(1);
    }
    snprintf(path, need, "%s/%s", dir, name);
    return path;
}

static void mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t len = strlen(path);

    if (len == 0 || len >= sizeof buffer) {
        fprintf(stderr, "path too long: %s\n", path);
        exit(1);
    }
    memcpy(buffer, path, len + 1);
    for (char *p = buffer + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(buffer, 0777);
            *p = '/';
        }
    }
    mkdir(buffer, 0777);
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

static void write_env(const char *path, const kv *overrides, size_t count) {
    const char *keys[128];
    const char *values[128];
    size_t total = 0;

    for (size_t i = 0; i < ARRAY_LEN(base); i++) {
        keys[total] = base[i].key;
        values[total] = base[i].value;
        total++;
    }
    for (size_t i = 0; i < count; i++) {
        size_t found;

        for (found = 0; found < total; found++) {
            if (strcmp(keys[found], overrides[i].key) == 0) {
                break;
            }
        }
        if (found < total) {
            values[found] = overrides[i].value;
        } else {
            if (total == ARRAY_LEN(keys)) {
                fprintf(stderr, "too many env keys in test\n");
                exit(1);
            }
            keys[total] = overrides[i].key;
            values[total] = overrides[i].value;
            total++;
        }
    }

    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    for (size_t i = 0; i < total; i++) {
        if (values[i] != NULL) {
            fprintf(file, "%s=%s\n", keys[i], values[i]);
        }
    }
    fclose(file);
}

/* Build <root>/MODULE.bazel and <root>/deploy/aws/.env from base+overrides. */
static void repo_with_env(const kv *overrides, size_t count, char **root_out,
                          char **dir_out) {
    char *root = make_temp_root();
    char *dir = join_path(root, "deploy/aws");
    char *marker = join_path(root, "MODULE.bazel");
    char *env = join_path(dir, ".env");

    mkdir_p(dir);
    write_text(marker, "");
    write_env(env, overrides, count);

    free(marker);
    free(env);
    *root_out = root;
    *dir_out = dir;
}

/* Save/restore stderr around expected-failure loads. */
static int saved_stderr = -1;

static void stderr_to(const char *path) {
    int fd;

    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    dup2(fd, STDERR_FILENO);
    close(fd);
}

static void stderr_restore(void) {
    fflush(stderr);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
        saved_stderr = -1;
    }
}

static int load_silent(const char *dir, int region_explicit,
                       const char *region_flag, stackctl_config **cfg) {
    int rc;

    stderr_to("/dev/null");
    rc = config_load(dir, region_explicit, region_flag, cfg);
    stderr_restore();
    return rc;
}

static void expect_invalid(const char *label, const kv *overrides,
                           size_t count) {
    char *root = NULL;
    char *dir = NULL;
    stackctl_config *cfg = NULL;
    int rc;

    repo_with_env(overrides, count, &root, &dir);
    rc = load_silent(dir, 0, NULL, &cfg);
    CHECK(rc != 0, label);
    CHECK(cfg == NULL, label);
    config_free(cfg);
    free(root);
    free(dir);
}

static stackctl_config *load_valid_repo(const char *label, const kv *overrides,
                                        size_t count, char **root_out,
                                        char **dir_out) {
    stackctl_config *cfg = NULL;
    int rc;

    repo_with_env(overrides, count, root_out, dir_out);
    rc = config_load(*dir_out, 0, NULL, &cfg);
    CHECK(rc == 0, label);
    if (rc != 0) {
        return NULL;
    }
    return cfg;
}

/* ------------------------------------------------------------------------- */
/* Parser                                                                    */
/* ------------------------------------------------------------------------- */

static void test_parser(void) {
    char *root = make_temp_root();
    char *path = join_path(root, "sample.env");
    config_envfile *ef = NULL;
    char err[256];

    write_text(path,
               "# comment\n"
               "\n"
               "export PROJECT=\"movie\"\n"
               "VALUE_WITH_EQUALS=a=b\n"
               "SINGLE='x y'\n"
               "EMPTY=\n"
               "  SPACED  =  kept  \n");
    CHECK(config_envfile_load(path, &ef, err, sizeof err) == 0, "parse sample");
    CHECK(strcmp(config_envfile_get(ef, "PROJECT"), "movie") == 0, "quoted");
    CHECK(strcmp(config_envfile_get(ef, "VALUE_WITH_EQUALS"), "a=b") == 0,
          "literal equals");
    CHECK(strcmp(config_envfile_get(ef, "SINGLE"), "x y") == 0, "single quote");
    CHECK(strcmp(config_envfile_get(ef, "EMPTY"), "") == 0, "empty value");
    CHECK(strcmp(config_envfile_get(ef, "SPACED"), "  kept  ") == 0,
          "inner whitespace literal");
    CHECK(config_envfile_count(ef) == 5, "entry count");
    config_envfile_free(ef);

    write_text(path, "A=1\nA=2\n");
    CHECK(config_envfile_load(path, &ef, err, sizeof err) != 0, "duplicate key");
    CHECK(ef == NULL, "duplicate leaves out null");

    write_text(path, "NO_EQUALS\n");
    CHECK(config_envfile_load(path, &ef, err, sizeof err) != 0, "malformed line");

    free(path);
    free(root);
}

/* ------------------------------------------------------------------------- */
/* Load + getters                                                            */
/* ------------------------------------------------------------------------- */

static void test_envfile_enumeration(void) {
    char *root = make_temp_root();
    char *path = join_path(root, "ordered.env");
    config_envfile *ef = NULL;
    char err[256];

    write_text(path, "ONE=1\nTWO=2\nTHREE=3\n");
    CHECK(config_envfile_load(path, &ef, err, sizeof err) == 0,
          "parse ordered env");
    CHECK(config_envfile_count(ef) == 3, "ordered count");
    CHECK(strcmp(config_envfile_key_at(ef, 0), "ONE") == 0, "key_at keeps order 0");
    CHECK(strcmp(config_envfile_key_at(ef, 1), "TWO") == 0, "key_at keeps order 1");
    CHECK(strcmp(config_envfile_key_at(ef, 2), "THREE") == 0, "key_at keeps order 2");
    CHECK(strcmp(config_envfile_value_at(ef, 0), "1") == 0, "value_at keeps order 0");
    CHECK(strcmp(config_envfile_value_at(ef, 1), "2") == 0, "value_at keeps order 1");
    CHECK(strcmp(config_envfile_value_at(ef, 2), "3") == 0, "value_at keeps order 2");
    CHECK(config_envfile_key_at(ef, 3) == NULL, "key_at past end is NULL");
    CHECK(config_envfile_value_at(ef, 3) == NULL, "value_at past end is NULL");
    CHECK(config_envfile_get(ef, "MISSING") == NULL, "get absent key is NULL");
    config_envfile_free(ef);

    CHECK(config_envfile_count(NULL) == 0, "count NULL is 0");
    CHECK(config_envfile_key_at(NULL, 0) == NULL, "key_at NULL is NULL");
    CHECK(config_envfile_value_at(NULL, 0) == NULL, "value_at NULL is NULL");

    free(path);
    free(root);
}

static void test_envfile_errors(void) {
    char *root = make_temp_root();
    char *path = join_path(root, "envfile.env");
    char *missing = join_path(root, "absent.env");
    config_envfile *ef = NULL;
    char err[256];

    /* Missing file: fail, out untouched, err populated. */
    CHECK(config_envfile_load(missing, &ef, err, sizeof err) != 0,
          "missing envfile rejected");
    CHECK(ef == NULL, "missing envfile leaves out null");
    CHECK(err[0] != '\0', "missing envfile describes failure");

    /* NULL path: fail cleanly. */
    CHECK(config_envfile_load(NULL, &ef, err, sizeof err) != 0,
          "NULL path rejected");
    CHECK(ef == NULL, "NULL path leaves out null");

    /* Invalid key name (leading digit) is rejected. */
    write_text(path, "1BAD=x\n");
    CHECK(config_envfile_load(path, &ef, err, sizeof err) != 0,
          "invalid key name rejected");
    CHECK(ef == NULL, "invalid key leaves out null");

    /* Over-long key (>= ENVFILE_KEY_MAX) is rejected. */
    {
        char line[300];
        memset(line, 'A', 260);
        line[260] = '=';
        line[261] = 'x';
        line[262] = '\n';
        line[263] = '\0';
        write_text(path, line);
        CHECK(config_envfile_load(path, &ef, err, sizeof err) != 0,
              "over-long key rejected");
        CHECK(ef == NULL, "over-long key leaves out null");
    }

    free(missing);
    free(path);
    free(root);
}

static void test_valid_basic(void) {
    char *root = NULL;
    char *dir = NULL;
    stackctl_config *cfg = load_valid_repo("valid base", NULL, 0, &root, &dir);
    const char *const *arch;

    if (cfg == NULL) {
        free(root);
        free(dir);
        return;
    }
    CHECK(strcmp(config_project(cfg), "demo") == 0, "project getter");
    CHECK(strcmp(config_region(cfg), "us-east-1") == 0, "region getter");
    CHECK(strcmp(config_get(cfg, "PROJECT"), "demo") == 0, "config_get project");
    CHECK(strcmp(config_get(cfg, "REGION"), "us-east-1") == 0, "config_get region");
    CHECK(strcmp(config_get(cfg, "ROOT_VOLUME_TYPE"), "gp3") == 0, "default gp3");
    CHECK(strcmp(config_get(cfg, "SSH_USER"), "ec2-user") == 0, "default user");
    CHECK(strcmp(config_get(cfg, "BAZEL_COMMAND"), "bazel") == 0, "default bazel");
    CHECK(config_get(cfg, "SERVICE_UNIT") == NULL, "unset optional is NULL");
    arch = config_arch_list(cfg);
    CHECK(arch != NULL && strcmp(arch[0], "amd64") == 0 && arch[1] == NULL,
          "arch list amd64");
    config_free(cfg);
    free(root);
    free(dir);
}

/* ------------------------------------------------------------------------- */
/* PROJECT regex                                                             */
/* ------------------------------------------------------------------------- */

static void test_project_regex(void) {
    static const kv hyphen[] = {{"PROJECT", "movie-night"}};
    static const kv upper[] = {{"PROJECT", "Movie"}};
    static const kv digit[] = {{"PROJECT", "1movie"}};
    static const kv single[] = {{"PROJECT", "m"}};
    static const kv underscore[] = {{"PROJECT", "movie_night"}};

    expect_invalid("PROJECT rejects hyphen", hyphen, ARRAY_LEN(hyphen));
    expect_invalid("PROJECT rejects uppercase", upper, ARRAY_LEN(upper));
    expect_invalid("PROJECT rejects leading digit", digit, ARRAY_LEN(digit));
    expect_invalid("PROJECT rejects single char", single, ARRAY_LEN(single));
    expect_invalid("PROJECT rejects underscore", underscore,
                   ARRAY_LEN(underscore));

    {
        static const kv ok[] = {{"PROJECT", "movie123"}};
        char *root = NULL;
        char *dir = NULL;
        stackctl_config *cfg =
            load_valid_repo("PROJECT accepts [a-z][a-z0-9]+", ok,
                            ARRAY_LEN(ok), &root, &dir);
        config_free(cfg);
        free(root);
        free(dir);
    }
}

/* ------------------------------------------------------------------------- */
/* Per-region length bound                                                   */
/* ------------------------------------------------------------------------- */

static void test_project_length_bound(void) {
    /* ap-southeast-2 is 14 chars: limit = 63 - 24 - 14 = 25. */
    static const kv limit_ok[] = {{"REGION", "ap-southeast-2"},
                                  {"PROJECT", "abcdefghijklmnopqrstuvwxy"}};
    static const kv limit_bad[] = {{"REGION", "ap-southeast-2"},
                                   {"PROJECT", "abcdefghijklmnopqrstuvwxyz"}};
    char *root = NULL;
    char *dir = NULL;
    char *err_path;
    stackctl_config *cfg;

    cfg = load_valid_repo("project at limit accepted", limit_ok,
                          ARRAY_LEN(limit_ok), &root, &dir);
    CHECK(cfg != NULL, "limit boundary loads");
    config_free(cfg);
    free(root);
    free(dir);

    repo_with_env(limit_bad, ARRAY_LEN(limit_bad), &root, &dir);
    err_path = join_path(root, "stderr.txt");
    stderr_to(err_path);
    cfg = NULL;
    CHECK(config_load(dir, 0, NULL, &cfg) != 0, "project over limit rejected");
    stderr_restore();
    CHECK(cfg == NULL, "over limit leaves out null");
    {
        FILE *file = fopen(err_path, "r");
        char message[1024] = {0};

        if (file != NULL) {
            size_t read = fread(message, 1, sizeof message - 1, file);
            message[read] = '\0';
            fclose(file);
        }
        CHECK(strstr(message, "PROJECT") != NULL, "limit error names PROJECT");
        CHECK(strstr(message, "63") != NULL, "limit error names the 63 limit");
    }
    config_free(cfg);
    free(err_path);
    free(root);
    free(dir);
}

/* ------------------------------------------------------------------------- */
/* Region consistency                                                        */
/* ------------------------------------------------------------------------- */

static void test_region_consistency(void) {
    static const kv us_east[] = {{"REGION", "us-east-1"}};
    static const kv eu_west[] = {{"REGION", "eu-west-1"}};
    char *root = NULL;
    char *dir = NULL;
    char *variant;
    stackctl_config *cfg = NULL;

    /* Plain .env declaring a region that has a sibling variant -> error. */
    repo_with_env(NULL, 0, &root, &dir);
    variant = join_path(dir, ".env.us-east-1");
    write_env(variant, us_east, ARRAY_LEN(us_east));
    CHECK(load_silent(dir, 0, NULL, &cfg) != 0,
          "plain .env rejects region with variant");
    CHECK(cfg == NULL, "plain/variant leaves out null");
    config_free(cfg);
    CHECK(unlink(variant) == 0, "remove sibling variant");
    free(variant);

    /* Explicit region loads .env.<region> and must match exactly. */
    variant = join_path(dir, ".env.eu-west-1");
    write_env(variant, eu_west, ARRAY_LEN(eu_west));
    cfg = NULL;
    CHECK(config_load(dir, 1, "eu-west-1", &cfg) == 0, "variant load");
    if (cfg != NULL) {
        CHECK(strcmp(config_region(cfg), "eu-west-1") == 0, "variant region");
    }
    config_free(cfg);
    free(variant);

    /* Absent variant -> error. */
    cfg = NULL;
    CHECK(load_silent(dir, 1, "eu-central-1", &cfg) != 0,
          "absent variant rejected");
    CHECK(cfg == NULL, "absent variant out null");
    config_free(cfg);

    /* Variant whose REGION disagrees with the flag -> error. */
    variant = join_path(dir, ".env.eu-central-1");
    write_env(variant, us_east, ARRAY_LEN(us_east));
    cfg = NULL;
    CHECK(load_silent(dir, 1, "eu-central-1", &cfg) != 0,
          "variant region mismatch rejected");
    CHECK(cfg == NULL, "mismatch out null");
    config_free(cfg);
    free(variant);

    /* A plain .env with no matching sibling still loads. */
    cfg = NULL;
    CHECK(config_load(dir, 0, NULL, &cfg) == 0, "plain without sibling loads");
    config_free(cfg);

    free(root);
    free(dir);
}

/* ------------------------------------------------------------------------- */
/* Repo root walk-up                                                         */
/* ------------------------------------------------------------------------- */

static void test_repo_root(void) {
    char *root = NULL;
    char *dir = NULL;
    char *resolved = NULL;
    char *expected = NULL;
    stackctl_config *cfg = NULL;

    repo_with_env(NULL, 0, &root, &dir);
    CHECK(config_repo_root(dir, &resolved) == 0, "repo root found");
    expected = realpath(root, NULL);
    if (resolved != NULL && expected != NULL) {
        CHECK(strcmp(resolved, expected) == 0, "repo root equals checkout root");
    }
    free(resolved);
    free(expected);
    free(root);
    free(dir);

    /* No MODULE.bazel anywhere above the config dir -> error. */
    {
        char *plain = make_temp_root();
        char *plain_dir = join_path(plain, "deploy/aws");
        char *env;

        mkdir_p(plain_dir);
        env = join_path(plain_dir, ".env");
        write_env(env, NULL, 0);
        resolved = NULL;
        CHECK(config_repo_root(plain_dir, &resolved) == ENOENT,
              "missing MODULE.bazel is ENOENT");
        CHECK(resolved == NULL, "missing root out null");
        cfg = NULL;
        CHECK(load_silent(plain_dir, 0, NULL, &cfg) != 0,
              "load fails without repo root");
        config_free(cfg);
        free(env);
        free(plain_dir);
        free(plain);
    }

    /* Config file symlinked outside the repo root -> error. */
    repo_with_env(NULL, 0, &root, &dir);
    {
        char *outside_root = make_temp_root();
        char *outside = join_path(outside_root, "escaped.env");
        char *env = join_path(dir, ".env");

        write_env(outside, NULL, 0);
        unlink(env);
        CHECK(symlink(outside, env) == 0, "symlink config outside root");
        cfg = NULL;
        CHECK(load_silent(dir, 0, NULL, &cfg) != 0,
              "config outside repo root rejected");
        CHECK(cfg == NULL, "outside root out null");
        config_free(cfg);
        free(env);
        free(outside);
        free(outside_root);
    }
    free(root);
    free(dir);
}

/* ------------------------------------------------------------------------- */
/* Relative --project resolution                                             */
/* ------------------------------------------------------------------------- */

static void test_relative_resolution(void) {
    char *root = NULL;
    char *dir = NULL;
    char saved_cwd[PATH_MAX];
    stackctl_config *cfg = NULL;

    repo_with_env(NULL, 0, &root, &dir);
    CHECK(getcwd(saved_cwd, sizeof saved_cwd) != NULL, "save cwd");

    CHECK(chdir("/tmp") == 0, "chdir /tmp");
    CHECK(setenv("BUILD_WORKING_DIRECTORY", root, 1) == 0, "set build cwd");
    cfg = NULL;
    CHECK(config_load("deploy/aws", 0, NULL, &cfg) == 0,
          "relative resolved via BUILD_WORKING_DIRECTORY");
    config_free(cfg);

    CHECK(unsetenv("BUILD_WORKING_DIRECTORY") == 0, "unset build cwd");
    CHECK(chdir(root) == 0, "chdir repo root");
    cfg = NULL;
    CHECK(config_load("deploy/aws", 0, NULL, &cfg) == 0,
          "relative resolved via process cwd");
    config_free(cfg);

    CHECK(chdir("/tmp") == 0, "chdir /tmp again");
    cfg = NULL;
    CHECK(load_silent("deploy/aws", 0, NULL, &cfg) != 0,
          "relative fails when cwd has no config");
    config_free(cfg);

    CHECK(chdir(saved_cwd) == 0, "restore cwd");
    unsetenv("BUILD_WORKING_DIRECTORY");
    free(root);
    free(dir);
}

/* ------------------------------------------------------------------------- */
/* Unknown keys / required keys                                             */
/* ------------------------------------------------------------------------- */

static void test_unknown_and_required(void) {
    static const kv unknown[] = {{"FOO", "bar"}};
    static const kv no_project[] = {{"PROJECT", NULL}};
    static const kv no_defaults[] = {{"SSH_PORT", NULL},
                                     {"SETUP_ENTRYPOINT", NULL}};
    static const kv no_cidr[] = {{"OPERATOR_CIDR", NULL}};
    static const kv empty_cidr[] = {{"OPERATOR_CIDR", ""}};

    expect_invalid("unknown key rejected", unknown, ARRAY_LEN(unknown));
    expect_invalid("missing PROJECT rejected", no_project,
                   ARRAY_LEN(no_project));
    expect_invalid("missing OPERATOR_CIDR rejected", no_cidr,
                   ARRAY_LEN(no_cidr));

    {
        char *root = NULL;
        char *dir = NULL;
        stackctl_config *cfg =
            load_valid_repo("SSH_PORT/SETUP_ENTRYPOINT default when unset",
                            no_defaults, ARRAY_LEN(no_defaults), &root, &dir);
        CHECK(cfg != NULL, "optional defaults load");
        if (cfg != NULL) {
            CHECK(strcmp(config_get(cfg, "SSH_PORT"), "22") == 0,
                  "SSH_PORT defaults to 22");
            CHECK(strcmp(config_get(cfg, "SETUP_ENTRYPOINT"), "deploy.sh") == 0,
                  "SETUP_ENTRYPOINT defaults to deploy.sh");
        }
        config_free(cfg);
        free(root);
        free(dir);
    }
    {
        char *root = NULL;
        char *dir = NULL;
        stackctl_config *cfg =
            load_valid_repo("empty OPERATOR_CIDR allowed", empty_cidr,
                            ARRAY_LEN(empty_cidr), &root, &dir);
        CHECK(cfg != NULL, "empty OPERATOR_CIDR loads");
        if (cfg != NULL) {
            CHECK(strcmp(config_get(cfg, "OPERATOR_CIDR"), "") == 0,
                  "empty OPERATOR_CIDR preserved");
        }
        config_free(cfg);
        free(root);
        free(dir);
    }
}

/* ------------------------------------------------------------------------- */
/* Cross-key consistency matrix                                              */
/* ------------------------------------------------------------------------- */

static void test_cross_keys(void) {
    /* arm64 requires INSTANCE_TYPES_ARM64. */
    static const kv arm64_missing[] = {
        {"ARCH", "arm64"}, {"AMI_POLICY", "baked"}, {"AMI_ID_AMD64", NULL}};
    static const kv arm64_ok[] = {{"ARCH", "arm64"},
                                  {"AMI_POLICY", "baked"},
                                  {"AMI_ID_AMD64", NULL},
                                  {"INSTANCE_TYPES_ARM64", "g5g.2xlarge"}};
    /* pinned requires AMI_ID_AMD64 for amd64. */
    static const kv pinned_missing[] = {{"AMI_ID_AMD64", NULL}};
    /* ssm requires AMI_SSM_* and forbids AMI_ID_*. */
    static const kv ssm_missing[] = {{"AMI_POLICY", "ssm"},
                                     {"AMI_ID_AMD64", NULL}};
    static const kv ssm_ok[] = {{"AMI_POLICY", "ssm"},
                                {"AMI_ID_AMD64", NULL},
                                {"AMI_SSM_AMD64",
                                 "/aws/service/ami-amazon-linux-latest/x"}};
    static const kv ssm_with_id[] = {{"AMI_POLICY", "ssm"},
                                     {"AMI_SSM_AMD64",
                                      "/aws/service/ami-amazon-linux-latest/x"}};
    static const kv ssm_bad_path[] = {{"AMI_POLICY", "ssm"},
                                      {"AMI_ID_AMD64", NULL},
                                      {"AMI_SSM_AMD64", "not-absolute"}};
    /* Spot alerts ↔ email. */
    static const kv alerts_no_email[] = {{"ENABLE_SPOT_ALERTS", "true"}};
    static const kv alerts_ok[] = {{"ENABLE_SPOT_ALERTS", "true"},
                                   {"SPOT_ALERT_EMAIL", "ops@example.com"}};
    static const kv alerts_off_email[] = {{"SPOT_ALERT_EMAIL", "ops@example.com"}};
    /* DDNS pair. */
    static const kv ddns_onbox_missing[] = {{"DDNS_ONBOX", "true"}};
    static const kv ddns_onbox_ok[] = {{"DDNS_ONBOX", "true"},
                                       {"DDNS_HOST", "home"},
                                       {"DDNS_DOMAIN", "example.com"}};
    static const kv ddns_half[] = {{"DDNS_HOST", "home"}};
    /* Enums / scalars. */
    static const kv bad_policy[] = {{"AMI_POLICY", "magic"}};
    static const kv bad_arch[] = {{"ARCH", "x86"}};
    static const kv bad_spot[] = {{"SPOT_DEFAULT", "yes"}};
    static const kv bad_size[] = {{"ROOT_VOLUME_SIZE", "0"}};
    static const kv bad_port[] = {{"SSH_PORT", "70000"}};
    /* Bucket modules. */
    static const kv no_artifact[] = {{"BUCKET_MODULES", "cert"}};
    static const kv bad_module[] = {{"BUCKET_MODULES", "artifact,history"}};
    /* Ingress. */
    static const kv ingress_bad_port[] = {{"INGRESS_TCP", "99999"}};
    static const kv ingress_empty_cidr[] = {{"INGRESS_TCP", "443:"}};

    expect_invalid("arm64 without INSTANCE_TYPES_ARM64", arm64_missing,
                   ARRAY_LEN(arm64_missing));
    expect_invalid("pinned without AMI_ID_AMD64", pinned_missing,
                   ARRAY_LEN(pinned_missing));
    expect_invalid("ssm without AMI_SSM_AMD64", ssm_missing,
                   ARRAY_LEN(ssm_missing));
    expect_invalid("ssm with AMI_ID_AMD64", ssm_with_id,
                   ARRAY_LEN(ssm_with_id));
    expect_invalid("ssm non-absolute parameter", ssm_bad_path,
                   ARRAY_LEN(ssm_bad_path));
    expect_invalid("spot alerts without email", alerts_no_email,
                   ARRAY_LEN(alerts_no_email));
    expect_invalid("DDNS_ONBOX without host/domain", ddns_onbox_missing,
                   ARRAY_LEN(ddns_onbox_missing));
    expect_invalid("DDNS_HOST without DDNS_DOMAIN", ddns_half,
                   ARRAY_LEN(ddns_half));
    expect_invalid("invalid AMI_POLICY", bad_policy, ARRAY_LEN(bad_policy));
    expect_invalid("invalid ARCH", bad_arch, ARRAY_LEN(bad_arch));
    expect_invalid("invalid SPOT_DEFAULT", bad_spot, ARRAY_LEN(bad_spot));
    expect_invalid("invalid ROOT_VOLUME_SIZE", bad_size, ARRAY_LEN(bad_size));
    expect_invalid("invalid SSH_PORT", bad_port, ARRAY_LEN(bad_port));
    expect_invalid("BUCKET_MODULES without artifact", no_artifact,
                   ARRAY_LEN(no_artifact));
    expect_invalid("BUCKET_MODULES unknown module", bad_module,
                   ARRAY_LEN(bad_module));
    expect_invalid("invalid ingress port", ingress_bad_port,
                   ARRAY_LEN(ingress_bad_port));
    expect_invalid("ingress with empty cidr", ingress_empty_cidr,
                   ARRAY_LEN(ingress_empty_cidr));

    /* Positive counterparts load. */
    {
        struct {
            const char *label;
            const kv *overrides;
            size_t count;
        } cases[] = {
            {"arm64 with INSTANCE_TYPES_ARM64", arm64_ok, ARRAY_LEN(arm64_ok)},
            {"ssm with AMI_SSM_AMD64", ssm_ok, ARRAY_LEN(ssm_ok)},
            {"spot alerts with email", alerts_ok, ARRAY_LEN(alerts_ok)},
            {"spot email accepted while alerts off", alerts_off_email,
             ARRAY_LEN(alerts_off_email)},
            {"DDNS_ONBOX with pair", ddns_onbox_ok, ARRAY_LEN(ddns_onbox_ok)},
        };

        for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
            char *root = NULL;
            char *dir = NULL;
            stackctl_config *cfg = load_valid_repo(
                cases[i].label, cases[i].overrides, cases[i].count, &root, &dir);

            CHECK(cfg != NULL, cases[i].label);
            config_free(cfg);
            free(root);
            free(dir);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Architecture list variants                                                */
/* ------------------------------------------------------------------------- */

static void test_arch_list_variants(void) {
    static const kv arm64_ok[] = {{"ARCH", "arm64"},
                                  {"AMI_POLICY", "baked"},
                                  {"AMI_ID_AMD64", NULL},
                                  {"INSTANCE_TYPES_ARM64", "g5g.2xlarge"}};
    static const kv both_ok[] = {{"ARCH", "both"},
                                 {"AMI_POLICY", "baked"},
                                 {"AMI_ID_AMD64", NULL},
                                 {"INSTANCE_TYPES_ARM64", "g5g.2xlarge"}};
    char *root = NULL;
    char *dir = NULL;
    stackctl_config *cfg;
    const char *const *arch;

    cfg = load_valid_repo("arch list arm64", arm64_ok, ARRAY_LEN(arm64_ok),
                          &root, &dir);
    if (cfg != NULL) {
        arch = config_arch_list(cfg);
        CHECK(arch != NULL && strcmp(arch[0], "arm64") == 0 && arch[1] == NULL,
              "arch list arm64");
    }
    config_free(cfg);
    free(root);
    free(dir);

    cfg = load_valid_repo("arch list both", both_ok, ARRAY_LEN(both_ok), &root,
                          &dir);
    if (cfg != NULL) {
        arch = config_arch_list(cfg);
        CHECK(arch != NULL && strcmp(arch[0], "amd64") == 0 &&
                  strcmp(arch[1], "arm64") == 0 && arch[2] == NULL,
              "arch list both");
    }
    config_free(cfg);
    free(root);
    free(dir);

    CHECK(config_arch_list(NULL) == NULL, "arch list NULL config");
}

/* ------------------------------------------------------------------------- */
/* BUILD_WORKING_DIRECTORY accessor                                          */
/* ------------------------------------------------------------------------- */

static void test_build_working_directory(void) {
    CHECK(setenv("BUILD_WORKING_DIRECTORY", "/tmp/stackctl-build", 1) == 0,
          "set BUILD_WORKING_DIRECTORY");
    CHECK(strcmp(config_build_working_directory(), "/tmp/stackctl-build") == 0,
          "build working directory value");

    CHECK(setenv("BUILD_WORKING_DIRECTORY", "", 1) == 0,
          "set empty BUILD_WORKING_DIRECTORY");
    CHECK(config_build_working_directory() == NULL,
          "empty build working directory is NULL");

    CHECK(unsetenv("BUILD_WORKING_DIRECTORY") == 0,
          "unset BUILD_WORKING_DIRECTORY");
    CHECK(config_build_working_directory() == NULL,
          "unset build working directory is NULL");
}

/* ------------------------------------------------------------------------- */
/* config_dir accessor                                                       */
/* ------------------------------------------------------------------------- */

static void test_config_dir_accessor(void) {
    static const kv eu_west[] = {{"REGION", "eu-west-1"}};
    char *root = NULL;
    char *dir = NULL;
    char *variant = NULL;
    char resolved[PATH_MAX];
    stackctl_config *cfg = NULL;

    cfg = load_valid_repo("config_dir default load", NULL, 0, &root, &dir);
    CHECK(cfg != NULL, "default config loaded");
    CHECK(realpath(dir, resolved) != NULL, "realpath default config dir");
    CHECK(config_dir(cfg) != NULL && strcmp(config_dir(cfg), resolved) == 0,
          "default accessor returns the loaded directory");
    config_free(cfg);

    variant = join_path(dir, ".env.eu-west-1");
    write_env(variant, eu_west, ARRAY_LEN(eu_west));
    cfg = NULL;
    CHECK(config_load(dir, 1, "eu-west-1", &cfg) == 0,
          "region variant config loaded");
    CHECK(config_dir(cfg) != NULL && strcmp(config_dir(cfg), resolved) == 0,
          "region variant accessor returns the same directory");
    config_free(cfg);

    free(root);
    free(dir);
    free(variant);

    {
        /* An explicit --project outside `deploy/aws` must be reported as-is. */
        char *other_root = make_temp_root();
        char *other_dir = join_path(other_root, "custom/config");
        char *marker = join_path(other_root, "MODULE.bazel");
        char *env = join_path(other_dir, ".env");
        char other_resolved[PATH_MAX];

        mkdir_p(other_dir);
        write_text(marker, "");
        write_env(env, NULL, 0);

        cfg = NULL;
        CHECK(config_load(other_dir, 0, NULL, &cfg) == 0,
              "custom --project config loaded");
        CHECK(realpath(other_dir, other_resolved) != NULL,
              "realpath custom config dir");
        CHECK(config_dir(cfg) != NULL &&
                  strcmp(config_dir(cfg), other_resolved) == 0,
              "--project override is reported by the accessor");
        config_free(cfg);

        free(other_root);
        free(other_dir);
        free(marker);
        free(env);
    }

    CHECK(config_dir(NULL) == NULL, "accessor is NULL-safe");
}

int main(void) {
    test_parser();
    test_envfile_enumeration();
    test_envfile_errors();
    test_valid_basic();
    test_project_regex();
    test_project_length_bound();
    test_region_consistency();
    test_repo_root();
    test_relative_resolution();
    test_unknown_and_required();
    test_cross_keys();
    test_arch_list_variants();
    test_build_working_directory();
    test_config_dir_accessor();

    if (failures != 0) {
        fprintf(stderr, "%d config test check(s) failed\n", failures);
        return 1;
    }
    printf("config_test: all checks passed\n");
    return 0;
}
