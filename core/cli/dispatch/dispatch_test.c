/*
 * dispatch_test.c — unit tests for the top-level CLI dispatcher.
 *
 * Covers the frozen command table, verb resolution, global-flag enforcement,
 * exit-code normalization, help/version rendering and the process pipeline's
 * no-project paths (help, version, no argument, unknown command). Real verbs
 * need a project config and are exercised by their own packages and the
 * integration harness; here the table and helpers are tested directly.
 */

#include "dispatch.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

typedef int (*run_fn)(void *ud);

struct run_call {
    int argc;
    char **argv;
};

static int call_run(void *ud) {
    struct run_call *call = ud;

    return cli_dispatch_run(call->argc, call->argv);
}

/*
 * Run `fn`, capturing everything written to file descriptor `fd`. Returns the
 * callback's value and copies the captured text into `out` (NUL-terminated).
 */
static int capture_fd(int fd, run_fn fn, void *ud, char *out, size_t cap) {
    int saved;
    int rc;
    size_t used;
    FILE *tmp;

    if (cap == 0) {
        return -1;
    }
    out[0] = '\0';
    fflush(NULL);
    saved = dup(fd);
    tmp = tmpfile();
    if (saved < 0 || tmp == NULL) {
        if (saved >= 0) {
            close(saved);
        }
        if (tmp != NULL) {
            fclose(tmp);
        }
        return -1;
    }
    if (dup2(fileno(tmp), fd) < 0) {
        close(saved);
        fclose(tmp);
        return -1;
    }
    rc = fn(ud);
    fflush(NULL);
    (void)dup2(saved, fd);
    close(saved);
    rewind(tmp);
    used = fread(out, 1, cap - 1, tmp);
    out[used] = '\0';
    fclose(tmp);
    return rc;
}

/* Read a FILE* the implementation already wrote into a local buffer. */
static void read_stream(FILE *stream, char *out, size_t cap) {
    size_t used;

    fflush(stream);
    rewind(stream);
    used = fread(out, 1, cap - 1, stream);
    out[used] = '\0';
}

static void test_table(void) {
    static const char *const expected[] = {
        "provision", "deploy", "refresh-ami", "launch",
        "terminate", "status", "start",       "stop",
    };
    size_t count = 0;
    const cli_command *table = cli_dispatch_table(&count);

    CHECK(table != NULL);
    CHECK(count == sizeof(expected) / sizeof(expected[0]));
    for (size_t i = 0; i < count && i < 8; i++) {
        int preview = strcmp(expected[i], "provision") == 0 ||
                      strcmp(expected[i], "deploy") == 0 ||
                      strcmp(expected[i], "refresh-ami") == 0;

        CHECK(table[i].name != NULL);
        CHECK(strcmp(table[i].name, expected[i]) == 0);
        CHECK(table[i].summary != NULL);
        CHECK(table[i].usage != NULL);
        CHECK(table[i].run != NULL);
        CHECK(table[i].mutates == cli_verb_mutates(expected[i]));
        CHECK(table[i].supports_dry_run == preview);
    }
    CHECK(cli_dispatch_table(NULL) != NULL);
}

static void test_find(void) {
    CHECK(cli_dispatch_find("status") != NULL);
    CHECK(strcmp(cli_dispatch_find("status")->name, "status") == 0);
    CHECK(cli_dispatch_find("refresh-ami") != NULL);
    CHECK(cli_dispatch_find("bogus") == NULL);
    CHECK(cli_dispatch_find(NULL) == NULL);
    CHECK(cli_dispatch_find("") == NULL);
}

static void test_normalize_rc(void) {
    for (int code = 0; code <= 7; code++) {
        CHECK(cli_dispatch_normalize_rc(code) == code);
    }
    CHECK(cli_dispatch_normalize_rc(EINVAL) == CLI_EXIT_USAGE);
    CHECK(cli_dispatch_normalize_rc(ENOMEM) == CLI_EXIT_USAGE);
    CHECK(cli_dispatch_normalize_rc(999) == CLI_EXIT_AWS);
    CHECK(cli_dispatch_normalize_rc(-EINVAL) == CLI_EXIT_USAGE);
}

static void test_check_globals(void) {
    cli_globals globals;
    char err[256];
    FILE *stream;

    memset(&globals, 0, sizeof(globals));
    globals.dry_run = 1;
    stream = tmpfile();
    CHECK(stream != NULL);
    if (stream != NULL) {
        CHECK(cli_dispatch_check_globals(cli_dispatch_find("status"), &globals,
                                         stream) == CLI_EXIT_USAGE);
        read_stream(stream, err, sizeof(err));
        CHECK(strstr(err, "--dry-run") != NULL);
        fclose(stream);
    }
    CHECK(cli_dispatch_check_globals(cli_dispatch_find("provision"), &globals,
                                     NULL) == CLI_EXIT_OK);
    CHECK(cli_dispatch_check_globals(cli_dispatch_find("deploy"), &globals,
                                     NULL) == CLI_EXIT_OK);
    globals.dry_run = 0;
    CHECK(cli_dispatch_check_globals(cli_dispatch_find("status"), &globals,
                                     NULL) == CLI_EXIT_OK);
    CHECK(cli_dispatch_check_globals(NULL, &globals, NULL) == CLI_EXIT_USAGE);
    CHECK(cli_dispatch_check_globals(cli_dispatch_find("status"), NULL, NULL) ==
          CLI_EXIT_USAGE);
}

static void test_help(void) {
    char text[4096];

    FILE *stream = tmpfile();
    CHECK(stream != NULL);
    if (stream == NULL) {
        return;
    }
    cli_dispatch_print_help(stream, "stackctl");
    read_stream(stream, text, sizeof(text));
    fclose(stream);
    CHECK(strstr(text, "Usage:") != NULL);
    CHECK(strstr(text, "Global flags:") != NULL);
    CHECK(strstr(text, "Commands:") != NULL);
    for (size_t i = 0; i < 8; i++) {
        const char *const names[] = {"provision", "deploy", "refresh-ami",
                                     "launch", "terminate", "status",
                                     "start", "stop"};
        CHECK(strstr(text, names[i]) != NULL);
    }
    /* A NULL stream is ignored, not a crash. */
    cli_dispatch_print_help(NULL, "stackctl");
}

static void test_version(void) {
    char path[] = "/tmp/stackctl-version-XXXXXX";
    char text[512];
    int fd = mkstemp(path);
    FILE *stream;
    size_t len;

    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    len = strlen("v9.9.9\n");
    CHECK(write(fd, "v9.9.9\n", len) == (ssize_t)len);
    close(fd);
    CHECK(setenv(CLI_DISPATCH_VERSION_ENV, path, 1) == 0);

    stream = tmpfile();
    CHECK(stream != NULL);
    if (stream != NULL) {
        CHECK(cli_dispatch_print_version(stream) == 0);
        read_stream(stream, text, sizeof(text));
        fclose(stream);
        CHECK(strstr(text, "v9.9.9") != NULL);
        CHECK(strstr(text, "spec rev 8") != NULL);
        CHECK(strchr(text, '\n') != NULL);
    }

    CHECK(setenv(CLI_DISPATCH_VERSION_ENV, "/nonexistent/stackctl-version", 1) ==
          0);
    stream = tmpfile();
    CHECK(stream != NULL);
    if (stream != NULL) {
        CHECK(cli_dispatch_print_version(stream) == 0);
        read_stream(stream, text, sizeof(text));
        fclose(stream);
        CHECK(strstr(text, "unknown") != NULL);
        CHECK(strstr(text, "spec rev 8") != NULL);
    }
    (void)unlink(path);
    (void)unsetenv(CLI_DISPATCH_VERSION_ENV);

    CHECK(cli_dispatch_print_version(NULL) == EINVAL);
}

static int write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");
    int ok;

    if (file == NULL) {
        return -1;
    }
    ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok ? 0 : -1;
}

/*
 * Simulate a Bazel runfiles tree in a temp directory. The binary is run from an
 * unrelated cwd so only the runfiles copy can supply the tag, mirroring the
 * documented consuming-build invocation `bazel run //deploy/aws:stackctl`
 * (cwd = consumer workspace, VERSION only in the runfiles tree).
 */
static void test_version_runfiles(void) {
    char root[] = "/tmp/stackctl-runfiles-XXXXXX";
    char other[] = "/tmp/stackctl-cwd-XXXXXX";
    char path[512];
    char cwd[4096];
    char text[512];
    FILE *stream;
    char *made = mkdtemp(root);
    char *othermade = mkdtemp(other);
    int ok = made != NULL && othermade != NULL;

    CHECK(ok);
    if (!ok) {
        return;
    }
    snprintf(path, sizeof(path), "%s/_main", made);
    ok = mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/_main/VERSION", made);
    ok = ok && write_text(path, "v7.7.7\n") == 0;
    snprintf(path, sizeof(path), "%s/stackctl", made);
    ok = ok && mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/stackctl/VERSION", made);
    ok = ok && write_text(path, "v7.7.7\n") == 0;
    CHECK(ok);

    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    CHECK(chdir(othermade) == 0);
    CHECK(setenv("RUNFILES_DIR", made, 1) == 0);
    (void)unsetenv(CLI_DISPATCH_VERSION_ENV);

    stream = tmpfile();
    CHECK(stream != NULL);
    if (stream != NULL) {
        CHECK(cli_dispatch_print_version(stream) == 0);
        read_stream(stream, text, sizeof(text));
        fclose(stream);
        CHECK(strstr(text, "v7.7.7") != NULL);
        CHECK(strstr(text, "unknown") == NULL);
    }

    (void)chdir(cwd);
    (void)unsetenv("RUNFILES_DIR");
    snprintf(path, sizeof(path), "%s/_main/VERSION", made);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/stackctl/VERSION", made);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/_main", made);
    (void)rmdir(path);
    snprintf(path, sizeof(path), "%s/stackctl", made);
    (void)rmdir(path);
    (void)rmdir(made);
    (void)rmdir(othermade);
}

/*
 * Build a runfiles tree whose only repo directory is `repo` (holding
 * `repo/VERSION`), run from an unrelated cwd so only the runfiles copy can
 * supply the tag, and assert the resolved version line. The repo directory is
 * parameterised because bzlmod names it canonically (`_main` for the root
 * module, `<module>+<version>` / `<module>+` for external modules).
 */
static void check_runfiles_repo_dir(const char *repo, const char *contents,
                                    const char *expected) {
    char root[] = "/tmp/stackctl-runfiles-repo-XXXXXX";
    char other[] = "/tmp/stackctl-cwd-repo-XXXXXX";
    char path[512];
    char cwd[4096];
    char text[512];
    FILE *stream;
    char *made = mkdtemp(root);
    char *othermade = mkdtemp(other);
    int ok = made != NULL && othermade != NULL;

    CHECK(ok);
    if (!ok) {
        return;
    }
    snprintf(path, sizeof(path), "%s/%s", made, repo);
    ok = mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/%s/VERSION", made, repo);
    ok = ok && write_text(path, contents) == 0;
    CHECK(ok);

    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    CHECK(chdir(othermade) == 0);
    CHECK(setenv("RUNFILES_DIR", made, 1) == 0);
    (void)unsetenv(CLI_DISPATCH_VERSION_ENV);

    stream = tmpfile();
    CHECK(stream != NULL);
    if (stream != NULL) {
        CHECK(cli_dispatch_print_version(stream) == 0);
        read_stream(stream, text, sizeof(text));
        fclose(stream);
        CHECK(strstr(text, expected) != NULL);
        CHECK(strstr(text, "unknown") == NULL);
    }

    (void)chdir(cwd);
    (void)unsetenv("RUNFILES_DIR");
    snprintf(path, sizeof(path), "%s/%s/VERSION", made, repo);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/%s", made, repo);
    (void)rmdir(path);
    (void)rmdir(made);
    (void)rmdir(othermade);
}

/* Runfiles trees name the module repo `<workspace>`; `_main` may be absent. */
static void test_version_runfiles_workspace_only(void) {
    check_runfiles_repo_dir("stackctl", "v8.8.8\n", "v8.8.8");
    check_runfiles_repo_dir("stackctl+0.2.0", "v8.8.9\n", "v8.8.9");
}

/*
 * Under bzlmod an external module's runfiles directory is its CANONICAL repo
 * name, `stackctl+` or `stackctl+<version>` (e.g. `stackctl+0.1.0`), so a
 * consumed `bazel run //deploy/aws:stackctl` has neither `_main` nor a plain
 * `stackctl` directory in its runfiles tree.
 */
static void test_version_runfiles_canonical(void) {
    check_runfiles_repo_dir("stackctl+0.1.0", "v5.5.5\n", "v5.5.5");
    check_runfiles_repo_dir("stackctl+", "v4.4.4\n", "v4.4.4");
}

/* `argv[0].runfiles` is the runfiles root when RUNFILES_DIR is not exported. */
static void test_version_argv_runfiles(void) {
    char root[] = "/tmp/stackctl-argv-XXXXXX";
    char other[] = "/tmp/stackctl-cwd-argv-XXXXXX";
    char path[512];
    char cwd[4096];
    char text[512];
    FILE *stream;
    char *made = mkdtemp(root);
    char *othermade = mkdtemp(other);
    int ok = made != NULL && othermade != NULL;

    CHECK(ok);
    if (!ok) {
        return;
    }
    snprintf(path, sizeof(path), "%s/stackctl-fake.runfiles", made);
    ok = mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/stackctl-fake.runfiles/_main", made);
    ok = ok && mkdir(path, 0700) == 0;
    snprintf(path, sizeof(path), "%s/stackctl-fake.runfiles/_main/VERSION",
             made);
    ok = ok && write_text(path, "v6.6.6\n") == 0;
    CHECK(ok);

    CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
    CHECK(chdir(othermade) == 0);
    (void)unsetenv("RUNFILES_DIR");
    (void)unsetenv(CLI_DISPATCH_VERSION_ENV);

    snprintf(path, sizeof(path), "%s/stackctl-fake", made);
    stream = tmpfile();
    CHECK(stream != NULL);
    if (stream != NULL) {
        CHECK(cli_dispatch_print_version_for(stream, path) == 0);
        read_stream(stream, text, sizeof(text));
        fclose(stream);
        CHECK(strstr(text, "v6.6.6") != NULL);
    }

    (void)chdir(cwd);
    snprintf(path, sizeof(path), "%s/stackctl-fake.runfiles/_main/VERSION",
             made);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/stackctl-fake.runfiles/_main", made);
    (void)rmdir(path);
    snprintf(path, sizeof(path), "%s/stackctl-fake.runfiles", made);
    (void)rmdir(path);
    (void)rmdir(made);
    (void)rmdir(othermade);
}

static void test_run_no_arguments(void) {
    char *argv[] = {"stackctl", NULL};
    struct run_call call = {1, argv};
    char err[4096];
    int rc = capture_fd(STDERR_FILENO, call_run, &call, err, sizeof(err));

    CHECK(rc == CLI_EXIT_USAGE);
    CHECK(strstr(err, "Usage:") != NULL);
    CHECK(strstr(err, "missing command") != NULL);
}

static void test_run_unknown_command(void) {
    char *argv[] = {"stackctl", "frobnicate", NULL};
    struct run_call call = {2, argv};
    char err[4096];
    int rc = capture_fd(STDERR_FILENO, call_run, &call, err, sizeof(err));

    CHECK(rc == CLI_EXIT_USAGE);
    CHECK(strstr(err, "unknown command") != NULL);
    CHECK(strstr(err, "frobnicate") != NULL);
}

static void test_run_help(void) {
    char *argv[] = {"stackctl", "--help", NULL};
    struct run_call call = {2, argv};
    char out[8192];
    int rc = capture_fd(STDOUT_FILENO, call_run, &call, out, sizeof(out));

    CHECK(rc == CLI_EXIT_OK);
    CHECK(strstr(out, "Usage:") != NULL);
    CHECK(strstr(out, "refresh-ami") != NULL);
}

static void test_run_command_help(void) {
    char *argv[] = {"stackctl", "--help", "provision", NULL};
    struct run_call call = {3, argv};
    char out[4096];
    int rc = capture_fd(STDOUT_FILENO, call_run, &call, out, sizeof(out));

    CHECK(rc == CLI_EXIT_OK);
    CHECK(strstr(out, "provision") != NULL);
    CHECK(strstr(out, "Usage:") != NULL);
    /*
     * provision keeps its option table package-private, so the dispatcher
     * renders the synopsis only rather than reaching into a peer package.
     */
    CHECK(strstr(out, "Options:") == NULL);
}

static void test_run_command_help_options(void) {
    char *argv[] = {"stackctl", "--help", "launch", NULL};
    struct run_call call = {3, argv};
    char out[4096];
    int rc = capture_fd(STDOUT_FILENO, call_run, &call, out, sizeof(out));

    CHECK(rc == CLI_EXIT_OK);
    CHECK(strstr(out, "Usage:") != NULL);
    CHECK(strstr(out, "Options:") != NULL);
    CHECK(strstr(out, "--arch") != NULL);
}

static void test_run_version(void) {
    char path[] = "/tmp/stackctl-version-run-XXXXXX";
    char *argv[] = {"stackctl", "--version", NULL};
    struct run_call call = {2, argv};
    char out[512];
    int fd = mkstemp(path);
    int rc;

    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(write(fd, "v1.2.3\n", 7) == 7);
    close(fd);
    CHECK(setenv(CLI_DISPATCH_VERSION_ENV, path, 1) == 0);
    rc = capture_fd(STDOUT_FILENO, call_run, &call, out, sizeof(out));
    CHECK(rc == CLI_EXIT_OK);
    CHECK(strstr(out, "v1.2.3") != NULL);
    CHECK(strstr(out, "spec rev 8") != NULL);
    (void)unlink(path);
    (void)unsetenv(CLI_DISPATCH_VERSION_ENV);
}

int main(void) {
    test_table();
    test_find();
    test_normalize_rc();
    test_check_globals();
    test_help();
    test_version();
    test_version_runfiles();
    test_version_runfiles_workspace_only();
    test_version_runfiles_canonical();
    test_version_argv_runfiles();
    test_run_no_arguments();
    test_run_unknown_command();
    test_run_help();
    test_run_command_help();
    test_run_command_help_options();
    test_run_version();

    if (failures != 0) {
        fprintf(stderr, "dispatch_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("dispatch_test: ok\n");
    return 0;
}
