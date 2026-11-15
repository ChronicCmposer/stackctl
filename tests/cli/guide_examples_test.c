/*
 * guide_examples_test.c — exercise the command examples in the maintainer docs.
 *
 * The onboarding and migration guides tell a maintainer to run `--version`,
 * `--help`, a fail-closed config validation, and then a real verb on a valid
 * draft `.env`. This test proves those examples against the built binary:
 *
 *   1. `--version` resolves the committed VERSION tag (never "unknown").
 *   2. `--help` lists all eight frozen verbs.
 *   3. An unknown `.env` key exits 1 before any AWS call.
 *   4. A valid draft `.env` passes config validation and then fails at the
 *      bazel preflight, proving the failure moved past the config boundary.
 *
 * No network and no real credentials are used. The fake PATH deliberately has
 * no `bazel`, so the last case stops at status's prerequisite check.
 */

#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY "test-secret-never-leaked"

static int failures;

#define CHECK(cond, message)                                                   \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (message), __FILE__,         \
                    __LINE__);                                                 \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ---------------------------------------------------------------------- */
/* Temporary filesystem helpers                                           */
/* ---------------------------------------------------------------------- */

static void write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    if (fputs(text, file) == EOF) {
        perror(path);
        exit(1);
    }
    if (fclose(file) != 0) {
        perror(path);
        exit(1);
    }
}

static void make_executable(const char *path) {
    write_text(path, "");
    if (chmod(path, 0700) != 0) {
        perror(path);
        exit(1);
    }
}

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

/* ---------------------------------------------------------------------- */
/* Fixture                                                                */
/* ---------------------------------------------------------------------- */

typedef struct fixture {
    char root[PATH_MAX];
    char config_dir[PATH_MAX];
    char bin_dir[PATH_MAX];
    char home[PATH_MAX];
    char state[PATH_MAX];
    char identity[PATH_MAX];
    char stdout_path[PATH_MAX];
    char stderr_path[PATH_MAX];
    char binary[PATH_MAX];
} fixture;

static const char *VALID_ENV =
    "PROJECT=demo\n"
    "REGION=us-east-1\n"
    "ARCH=amd64\n"
    "SPOT_DEFAULT=false\n"
    "AMI_POLICY=pinned\n"
    "AMI_ID_AMD64=ami-0123456789abcdef0\n"
    "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"
    "ROOT_VOLUME_SIZE=100\n"
    "KEY_NAME=demo-key\n"
    "SSH_IDENTITY=%s\n"
    "BUCKET_MODULES=artifact\n"
    "ENABLE_IMAGE_BUILDER=false\n"
    "SETUP_ENTRYPOINT=deploy.sh\n"
    "SSH_PORT=22\n"
    "SERVICE_UNIT=demo.service\n"
    "OPERATOR_CIDR=203.0.113.0/24\n"
    "INGRESS_TCP=443\n"
    "INGRESS_UDP=\n"
    "RELEASE_TARGETS=//app:deploy.tar.gz\n"
    "RELEASE_PREFIXES=releases/\n";

static void locate_binary(char out[PATH_MAX]) {
    const char *srcdir = getenv("TEST_SRCDIR");
    const char *workspace = getenv("TEST_WORKSPACE");
    const char *suffix = "core/cli/dispatch/stackctl";
    static const char *const roots[] = {"_main", "stackctl"};

    if (srcdir != NULL && workspace != NULL) {
        if (snprintf(out, PATH_MAX, "%s/%s/%s", srcdir, workspace, suffix) <
                PATH_MAX &&
            access(out, X_OK) == 0) {
            return;
        }
    }
    if (srcdir != NULL) {
        for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
            if (snprintf(out, PATH_MAX, "%s/%s/%s", srcdir, roots[i], suffix) <
                    PATH_MAX &&
                access(out, X_OK) == 0) {
                return;
            }
        }
    }
    fprintf(stderr, "cannot locate stackctl in runfiles\n");
    exit(1);
}

static void make_dir(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        perror(path);
        exit(1);
    }
}

static void fixture_init(fixture *fx) {
    char template[] = "/tmp/stackctl-guide-XXXXXX";
    char *root = mkdtemp(template);
    char path[PATH_MAX];
    char credentials[PATH_MAX];

    memset(fx, 0, sizeof *fx);
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof fx->root, "%s", root);
    snprintf(fx->config_dir, sizeof fx->config_dir, "%s/deploy/aws", fx->root);
    snprintf(fx->bin_dir, sizeof fx->bin_dir, "%s/bin", fx->root);
    snprintf(fx->home, sizeof fx->home, "%s/home", fx->root);
    snprintf(fx->state, sizeof fx->state, "%s/state", fx->root);
    snprintf(fx->identity, sizeof fx->identity, "%s/id_demo", fx->root);
    snprintf(fx->stdout_path, sizeof fx->stdout_path, "%s/stdout", fx->root);
    snprintf(fx->stderr_path, sizeof fx->stderr_path, "%s/stderr", fx->root);
    locate_binary(fx->binary);

    make_dir(fx->home);
    snprintf(path, sizeof path, "%s/.aws", fx->home);
    make_dir(path);
    snprintf(credentials, sizeof credentials, "%s/.aws/credentials", fx->home);
    write_text(credentials, "[demo]\n"
                            "aws_access_key_id = AKIAEXAMPLE\n"
                            "aws_secret_access_key = " SECRET_KEY "\n");

    snprintf(path, sizeof path, "%s/deploy", fx->root);
    make_dir(path);
    make_dir(fx->config_dir);
    snprintf(path, sizeof path, "%s/MODULE.bazel", fx->root);
    write_text(path, "");
    write_text(fx->identity, "");

    make_dir(fx->bin_dir);
    /* No bazel on PATH: status stops at the prerequisite check. */
    snprintf(path, sizeof path, "%s/ssh", fx->bin_dir);
    make_executable(path);
    snprintf(path, sizeof path, "%s/scp", fx->bin_dir);
    make_executable(path);
    snprintf(path, sizeof path, "%s/ssh-keyscan", fx->bin_dir);
    make_executable(path);

    make_dir(fx->state);
}

static void fixture_done(fixture *fx) {
    remove_tree(fx->root);
}

/* ---------------------------------------------------------------------- */
/* Driver                                                                 */
/* ---------------------------------------------------------------------- */

/* Run the binary with the fixture environment. `args` excludes argv[0]. */
static int run_cli(fixture *fx, char *const *args, size_t arg_count) {
    int out = open(fx->stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int err = open(fx->stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    char *argv[16];
    pid_t pid;
    int status = 0;

    if (out < 0 || err < 0 || arg_count + 2 > sizeof argv / sizeof argv[0]) {
        perror("open");
        exit(1);
    }
    argv[0] = fx->binary;
    for (size_t i = 0; i < arg_count; i++) {
        argv[i + 1] = args[i];
    }
    argv[arg_count + 1] = NULL;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid == 0) {
        if (dup2(out, STDOUT_FILENO) < 0 || dup2(err, STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(out);
        close(err);
        if (setenv("PATH", fx->bin_dir, 1) != 0 ||
            setenv("HOME", fx->home, 1) != 0 ||
            setenv("XDG_STATE_HOME", fx->state, 1) != 0) {
            _exit(126);
        }
        execv(fx->binary, argv);
        _exit(127);
    }
    close(out);
    close(err);
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        exit(1);
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 128 + WTERMSIG(status);
}

static char *read_file(const char *path) {
    FILE *file = fopen(path, "r");
    long size;
    char *buffer;

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
    if (buffer != NULL && fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        buffer = NULL;
    }
    fclose(file);
    return buffer;
}

static void write_env(fixture *fx, const char *suffix) {
    char path[PATH_MAX];
    char body[4096];
    size_t used = 0;

    snprintf(path, sizeof path, "%s/.env", fx->config_dir);
    used = (size_t)snprintf(body, sizeof body, VALID_ENV, fx->identity);
    if (suffix != NULL && used < sizeof body) {
        (void)snprintf(body + used, sizeof body - used, "%s", suffix);
    }
    write_text(path, body);
}

static void test_version(fixture *fx) {
    char *args[] = {"--version"};
    int rc = run_cli(fx, args, 1);
    char *out = read_file(fx->stdout_path);

    CHECK(rc == 0, "--version exits 0");
    CHECK(out != NULL, "--version writes stdout");
    if (out != NULL) {
        CHECK(strncmp(out, "stackctl ", 9) == 0,
              "--version starts with the program name");
        CHECK(strstr(out, "(spec rev ") != NULL,
              "--version reports the design-spec revision");
        CHECK(strstr(out, "unknown") == NULL,
              "--version resolves the committed VERSION tag");
    }
    free(out);
}

static void test_help(fixture *fx) {
    char *args[] = {"--help"};
    static const char *const verbs[] = {
        "provision", "deploy", "refresh-ami", "launch",
        "terminate", "status", "start",       "stop",
    };
    int rc = run_cli(fx, args, 1);
    char *out = read_file(fx->stdout_path);

    CHECK(rc == 0, "--help exits 0");
    CHECK(out != NULL, "--help writes stdout");
    if (out != NULL) {
        CHECK(strstr(out, "Commands:") != NULL, "--help lists commands");
        for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
            if (strstr(out, verbs[i]) == NULL) {
                fprintf(stderr, "FAIL: --help omits the %s verb (%s:%d)\n",
                        verbs[i], __FILE__, __LINE__);
                failures++;
            }
        }
    }
    free(out);
}

static void test_unknown_key(fixture *fx) {
    char *args[] = {"--project", fx->config_dir, "status"};
    int rc;
    char *err;

    write_env(fx, "TOTALLY_UNKNOWN=1\n");
    rc = run_cli(fx, args, 3);
    err = read_file(fx->stderr_path);
    CHECK(rc == 1, "unknown key exits 1");
    CHECK(err != NULL && strstr(err, "unknown configuration key") != NULL,
          "unknown key names the validation failure");
    free(err);
}

static void test_config_boundary(fixture *fx) {
    char *args[] = {"--project", fx->config_dir, "status"};
    int rc;
    char *err;

    write_env(fx, NULL);
    rc = run_cli(fx, args, 3);
    err = read_file(fx->stderr_path);
    CHECK(rc == 1, "valid draft config fails at the bazel preflight");
    CHECK(err != NULL && strstr(err, "BAZEL_COMMAND bazel not found") != NULL,
          "failure is the post-config bazel preflight");
    CHECK(err == NULL || strstr(err, "stackctl: config:") == NULL,
          "config validation passed before the preflight");
    free(err);
}

int main(void) {
    fixture fx;

    fixture_init(&fx);
    test_version(&fx);
    test_help(&fx);
    test_unknown_key(&fx);
    test_config_boundary(&fx);
    fixture_done(&fx);

    if (failures != 0) {
        fprintf(stderr, "guide_examples_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("guide_examples_test: ok\n");
    return 0;
}
