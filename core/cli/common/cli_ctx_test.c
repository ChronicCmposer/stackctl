/*
 * cli_ctx_test.c — context construction, verb registration helpers, lock
 * policy and signal bookkeeping.
 *
 * Builds throwaway repo roots under /tmp with a MODULE.bazel marker and a
 * deploy/aws/.env, then exercises cli_ctx_init against the real config/state
 * modules (which are the consumed interfaces from wave 1).
 */

#include "cli.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
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

static int argc_of(char **argv) {
    int argc = 0;

    while (argv[argc] != NULL) {
        argc++;
    }
    return argc;
}

/* ------------------------------------------------------------------------- */
/* Fixture: a minimal valid stackctl repo                                   */
/* ------------------------------------------------------------------------- */

static void mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t length = strlen(path);

    if (length == 0 || length >= sizeof(buffer)) {
        exit(1);
    }
    memcpy(buffer, path, length + 1);
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

static void write_env(const char *path) {
    static const char *const lines[] = {
        "PROJECT=demo",
        "REGION=us-east-1",
        "ARCH=amd64",
        "SPOT_DEFAULT=false",
        "AMI_POLICY=pinned",
        "AMI_ID_AMD64=ami-0123456789abcdef0",
        "INSTANCE_TYPES_AMD64=g4dn.xlarge",
        "ROOT_VOLUME_SIZE=100",
        "KEY_NAME=demo-key",
        "SSH_IDENTITY=/home/operator/.ssh/demo",
        "BUCKET_MODULES=artifact,cert",
        "ENABLE_IMAGE_BUILDER=false",
        "SETUP_ENTRYPOINT=deploy.sh",
        "SSH_PORT=22",
        "OPERATOR_CIDR=203.0.113.0/24",
        "INGRESS_TCP=443",
        "INGRESS_UDP=",
        "RELEASE_TARGETS=//app:deploy.tar.gz",
        "RELEASE_PREFIXES=releases/",
    };
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    for (size_t i = 0; i < ARRAY_LEN(lines); i++) {
        fprintf(file, "%s\n", lines[i]);
    }
    fclose(file);
}

static void make_repo(char **root_out, char *config_dir, size_t config_dir_size,
                      char *state_dir, size_t state_dir_size) {
    char template[] = "/tmp/stackctl-cli-XXXXXX";
    char *root = strdup(mkdtemp(template));
    char marker[PATH_MAX];
    char env[PATH_MAX];

    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(config_dir, config_dir_size, "%s/deploy/aws", root);
    mkdir_p(config_dir);
    snprintf(marker, sizeof(marker), "%s/MODULE.bazel", root);
    write_text(marker, "");
    snprintf(env, sizeof(env), "%s/.env", config_dir);
    write_env(env);
    snprintf(state_dir, state_dir_size, "%s/state", root);
    mkdir_p(state_dir);
    if (setenv("XDG_STATE_HOME", state_dir, 1) != 0) {
        perror("setenv");
        exit(1);
    }
    *root_out = root;
}

/* Silence expected-failure diagnostics. */
static int saved_stderr = -1;

static void stderr_quiet(void) {
    int fd;

    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
}

static void stderr_restore(void) {
    fflush(stderr);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
        saved_stderr = -1;
    }
}

static int init_silent(char **argv, cli_ctx **ctx) {
    int rc;

    stderr_quiet();
    rc = cli_ctx_init(argc_of(argv), argv, ctx);
    stderr_restore();
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Registration helpers                                                      */
/* ------------------------------------------------------------------------- */

static void test_registration(void) {
    static const cli_command commands[] = {
        {"provision", "p", "provision", NULL, 1, 1},
        {"deploy", "d", "deploy", NULL, 1, 1},
        {"refresh-ami", "r", "refresh-ami", NULL, 1, 1},
        {"launch", "l", "launch", NULL, 1, 1},
        {"terminate", "t", "terminate", NULL, 1, 1},
        {"status", "s", "status", NULL, 0, 0},
        {"start", "a", "start", NULL, 1, 0},
        {"stop", "o", "stop", NULL, 1, 0},
    };
    size_t count = 0;
    const char *const *names = cli_verb_names(&count);

    CHECK(names != NULL, "verb names");
    CHECK(count == 8, "eight frozen verbs");
    for (size_t i = 0; names != NULL && i < count; i++) {
        CHECK(cli_verb_known(names[i]) == 1, "known verb");
        CHECK(cli_command_find(commands, ARRAY_LEN(commands), names[i]) != NULL,
              "command find");
    }
    CHECK(cli_verb_known("bogus") == 0, "unknown verb");
    CHECK(cli_verb_known(NULL) == 0, "NULL verb");
    CHECK(cli_verb_mutates("status") == 0, "status is lockless");
    CHECK(cli_verb_mutates("provision") == 1, "provision locks");
    CHECK(cli_verb_mutates("deploy") == 1, "deploy locks");
    CHECK(cli_verb_mutates("refresh-ami") == 1, "refresh-ami locks");
    CHECK(cli_verb_mutates("launch") == 1, "launch locks");
    CHECK(cli_verb_mutates("terminate") == 1, "terminate locks");
    CHECK(cli_verb_mutates("start") == 1, "start locks");
    CHECK(cli_verb_mutates("stop") == 1, "stop locks");
    CHECK(cli_verb_mutates("bogus") == 0, "unknown does not lock");
    CHECK(cli_verb_mutates(NULL) == 0, "NULL does not lock");
    CHECK(cli_command_find(commands, ARRAY_LEN(commands), "bogus") == NULL,
          "find unknown");
    CHECK(cli_command_find(NULL, 0, "status") == NULL, "find NULL table");
    CHECK(cli_command_find(commands, ARRAY_LEN(commands), NULL) == NULL,
          "find NULL name");
    size_t ignored = 0;
    CHECK(cli_verb_names(&ignored) != NULL && ignored == 8, "names again");
}

/* ------------------------------------------------------------------------- */
/* Context: help / usage errors                                              */
/* ------------------------------------------------------------------------- */

static void test_help_and_usage_errors(void) {
    cli_ctx *ctx = NULL;
    {
        char *argv[] = {"stackctl", "--help", NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &ctx) == 0, "help init");
        CHECK(ctx != NULL, "help context");
        CHECK(cli_ctx_verb(ctx) == NULL, "help has no verb");
        CHECK(cli_ctx_config(ctx) == NULL, "help loads no config");
        CHECK(cli_ctx_state(ctx) == NULL, "help opens no state");
        CHECK(strcmp(cli_ctx_program(ctx), "stackctl") == 0, "program");
        cli_ctx_free(ctx);
        ctx = NULL;
    }
    {
        char *argv[] = {"stackctl", "--yes", "--help", NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &ctx) == 0, "yes/help init");
        CHECK(cli_confirm(ctx, "apply? [y/N] ") == CLI_CONFIRM_YES,
              "cli_confirm honours --yes without reading stdin");
        cli_ctx_free(ctx);
        ctx = NULL;
    }
    {
        char *argv[] = {"stackctl", "--version", NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &ctx) == 0, "version init");
        CHECK(ctx != NULL, "version context");
        CHECK(cli_ctx_config(ctx) == NULL, "version loads no config");
        cli_ctx_free(ctx);
        ctx = NULL;
    }
    {
        char *argv[] = {"stackctl", "--bogus", NULL};
        CHECK(init_silent(argv, &ctx) == EINVAL, "unknown global");
        CHECK(ctx == NULL, "failure leaves out NULL");
    }
    {
        char *argv[] = {"stackctl", "status", NULL};
        CHECK(init_silent(argv, &ctx) == EINVAL, "missing project");
        CHECK(ctx == NULL, "missing project leaves out NULL");
    }
    {
        char *argv[] = {"stackctl", "--project", "cfg", NULL};
        CHECK(init_silent(argv, &ctx) == EINVAL, "missing verb");
    }
    {
        char *argv[] = {"stackctl", NULL};
        CHECK(init_silent(argv, &ctx) == EINVAL, "empty command line");
    }
    {
        CHECK(cli_ctx_init(0, NULL, &ctx) == EINVAL, "zero argc");
        CHECK(cli_ctx_init(1, (char *[]){"stackctl"}, NULL) == EINVAL,
              "NULL out");
    }
    cli_ctx_free(NULL); /* safe */
}

/* ------------------------------------------------------------------------- */
/* Context: config/state/lock policy                                         */
/* ------------------------------------------------------------------------- */

static void test_context_success_and_locking(void) {
    char *root = NULL;
    char config_dir[PATH_MAX];
    char state_dir[PATH_MAX];
    cli_ctx *ctx = NULL;

    make_repo(&root, config_dir, sizeof(config_dir), state_dir,
              sizeof(state_dir));

    {
        char *argv[] = {"stackctl", "--project", config_dir, "status", "--json",
                        NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &ctx) == 0, "status init");
        CHECK(ctx != NULL, "status context");
        CHECK(strcmp(cli_ctx_verb(ctx), "status") == 0, "status verb");
        CHECK(cli_ctx_json(ctx) == 1, "json global after verb");
        CHECK(cli_ctx_yes(ctx) == 0, "yes default");
        CHECK(cli_ctx_dry_run(ctx) == 0, "dry-run default");
        CHECK(cli_ctx_lock_timeout(ctx) == -1, "lock timeout default");
        CHECK(cli_ctx_config(ctx) != NULL, "config loaded");
        CHECK(cli_ctx_state(ctx) != NULL, "state opened");
        CHECK(cli_ctx_verb_argc(ctx) == 1, "global extracted from verb argv");
        CHECK(strcmp(cli_ctx_verb_argv(ctx)[0], "status") == 0, "verb argv[0]");

        static const cli_option_spec specs[] = {
            {"verbose", 'v', 0, 0, NULL, "verbose output"},
        };
        cli_args args = {0};
        CHECK(cli_ctx_parse_args(ctx, specs, ARRAY_LEN(specs), &args) == 0,
              "ctx parse args");
        CHECK(cli_args_flag(&args, "verbose") == 0, "no verbose");
        cli_args_free(&args);
        cli_ctx_free(ctx);
        ctx = NULL;
    }

    /* A mutating verb takes the lock; a second mutating context times out. */
    cli_ctx *first = NULL;
    cli_ctx *second = NULL;
    cli_ctx *status = NULL;
    {
        char *argv[] = {"stackctl", "--project", config_dir, "deploy",
                        "--lock-timeout", "0", NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &first) == 0, "deploy init");
        CHECK(first != NULL, "deploy context");
        CHECK(cli_ctx_lock_timeout(first) == 0, "lock timeout parsed");
        CHECK(cli_ctx_verb_argc(first) == 1, "deploy argv has just the verb");
    }
    {
        char *argv[] = {"stackctl", "--project", config_dir, "deploy",
                        "--lock-timeout", "0", NULL};
        CHECK(init_silent(argv, &second) == ETIMEDOUT,
              "second mutating context times out");
        CHECK(second == NULL, "timeout leaves out NULL");
    }
    {
        char *argv[] = {"stackctl", "--project", config_dir, "status", NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &status) == 0,
              "status stays lockless while deploy holds the lock");
        CHECK(status != NULL, "lockless status context");
    }
    cli_ctx_free(status);
    cli_ctx_free(first);

    /* After release a new mutating context can lock again. */
    {
        char *argv[] = {"stackctl", "--project", config_dir, "start", NULL};
        CHECK(cli_ctx_init(argc_of(argv), argv, &ctx) == 0,
              "start init after unlock");
        CHECK(ctx != NULL, "start context");
        cli_ctx_free(ctx);
        ctx = NULL;
    }

    free(root);
}

/* ------------------------------------------------------------------------- */
/* Signals                                                                   */
/* ------------------------------------------------------------------------- */

static void test_signals(void) {
    cli_signal_install();
    CHECK(cli_signal_received() == 0, "no signal yet");
    CHECK(cli_signal_number() == 0, "no signal number yet");
    CHECK(raise(SIGTERM) == 0, "raise SIGTERM");
    CHECK(cli_signal_received() == 1, "first signal recorded");
    CHECK(cli_signal_number() == SIGTERM, "signal number recorded");
}

int main(void) {
    test_registration();
    test_help_and_usage_errors();
    test_context_success_and_locking();
    test_signals();

    if (failures != 0) {
        fprintf(stderr, "cli_ctx_test: %d check(s) failed\n", failures);
        return 1;
    }
    printf("cli_ctx_test: all checks passed\n");
    return 0;
}
