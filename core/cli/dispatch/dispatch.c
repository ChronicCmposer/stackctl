/*
 * dispatch.c — top-level command dispatch for `stackctl` (spec §4).
 *
 * This is the only place that knows the frozen verb table. It turns a raw
 * command line into either top-level help/version output (no project needed) or
 * a `cli_ctx` handed to one of the eight wave-4 entry points, and maps the
 * result onto the frozen exit-code contract. Diagnostics go to stderr; stdout
 * carries verb output, help and the version line only.
 */

#include "dispatch.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/cli/launch/launch_internal.h"
#include "core/cli/startstop/startstop_internal.h"
#include "core/cli/terminate/terminate_internal.h"

/* ------------------------------------------------------------------------- */
/* Frozen command table                                                      */
/* ------------------------------------------------------------------------- */

/*
 * `mutates` mirrors cli_verb_mutates(): every verb holds the project lock
 * except the read-only `status`. `supports_dry_run` marks the previewing verbs
 * from spec §4 (provision, deploy, refresh-ami); `--dry-run` is a usage error
 * for any other verb.
 */
static const cli_command commands[] = {
    {"provision", "deploy the project operator stack and verify identity",
     "provision [flags]", cli_cmd_provision, 1, 1},
    {"deploy", "build and publish a release, then update the infra stack",
     "deploy [--tag <vX.Y.Z>] [--allow-dirty] [--skip-build]", cli_cmd_deploy,
     1, 1},
    {"refresh-ami", "resolve SSM AMI floats and pin them into the config",
     "refresh-ami [flags]", cli_cmd_refresh_ami, 1, 1},
    {"launch", "launch and prepare a new instance",
     "launch [--arch <amd64|arm64>] [flags]", cli_cmd_launch, 1, 0},
    {"terminate", "terminate the project instance and park DDNS",
     "terminate [--instance-id <id>]", cli_cmd_terminate, 1, 0},
    {"status", "report stack, instance, drift and health status",
     "status [flags]", cli_cmd_status, 0, 0},
    {"start", "start the on-box service unit",
     "start [flags]", cli_cmd_start, 1, 0},
    {"stop", "stop the on-box service unit", "stop [flags]", cli_cmd_stop, 1, 0},
};

#define COMMAND_COUNT (sizeof(commands) / sizeof(commands[0]))

const cli_command *cli_dispatch_table(size_t *count) {
    if (count != NULL) {
        *count = COMMAND_COUNT;
    }
    return commands;
}

const cli_command *cli_dispatch_find(const char *verb) {
    return cli_command_find(commands, COMMAND_COUNT, verb);
}

/* ------------------------------------------------------------------------- */
/* Global-flag enforcement and exit mapping                                  */
/* ------------------------------------------------------------------------- */

int cli_dispatch_check_globals(const cli_command *command,
                               const cli_globals *globals, FILE *err) {
    FILE *stream = err != NULL ? err : stderr;

    if (command == NULL || globals == NULL) {
        return CLI_EXIT_USAGE;
    }
    if (globals->dry_run != 0 && command->supports_dry_run == 0) {
        fprintf(stream, "stackctl: --dry-run is not supported by '%s'\n",
                command->name != NULL ? command->name : "command");
        return CLI_EXIT_USAGE;
    }
    return CLI_EXIT_OK;
}

int cli_dispatch_normalize_rc(int rc) {
    /*
     * Verbs must return one of the frozen CLI_EXIT_* values; those pass through
     * unchanged. Compare against the enum members explicitly rather than a bare
     * 0..7 range check, so adding/reordering the frozen codes cannot silently
     * widen the accepted set. Everything else is an errno-style library value
     * and is classified by cli_rc_to_exit().
     *
     * Note: the frozen values occupy 0..7 and therefore numerically overlap the
     * first errno values (EPERM..E2BIG). That overlap is unavoidable in the
     * frozen ABI, so the guard against a verb leaking a raw errno is the verb
     * audit (cli_cmd_* must only return CLI_EXIT_*), not this mapper.
     */
    switch (rc) {
    case CLI_EXIT_OK:
    case CLI_EXIT_USAGE:
    case CLI_EXIT_AWS:
    case CLI_EXIT_VERIFY:
    case CLI_EXIT_LAUNCH:
    case CLI_EXIT_CLEANUP:
    case CLI_EXIT_FRESHNESS:
    case CLI_EXIT_SSH:
        return rc;
    default:
        break;
    }
    if (rc < 0) {
        return cli_rc_to_exit(-rc);
    }
    return cli_rc_to_exit(rc);
}

int cli_dispatch_verb_exit(int verb_rc) {
    int exit_code = cli_dispatch_normalize_rc(verb_rc);

    /*
     * A verb that handled the first signal on its standard failure path marks
     * it consumed; honor its returned code verbatim. Otherwise a successful
     * verb under a recorded signal keeps the frozen AWS mapping.
     */
    if (exit_code == CLI_EXIT_OK && cli_signal_received() != 0 &&
        !cli_signal_consumed()) {
        return CLI_EXIT_AWS;
    }
    return exit_code;
}

int cli_dispatch_unbuffer_stdio(void) {
    int rc = 0;

    /* A static musl binary fully buffers stdout/stderr when they are pipes or
     * files, hiding all progress until exit. Line/fully buffered streams also
     * make the periodic launch/terminate progress invisible to an operator
     * watching a redirected log. _IONBF makes every write hit the fd at once.
     * setvbuf() must run before any I/O on the stream; cli_dispatch_run calls
     * this first. A failure is non-fatal (output still works, just buffered). */
    if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
        rc = EIO;
    }
    if (setvbuf(stderr, NULL, _IONBF, 0) != 0) {
        rc = EIO;
    }
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Help and version                                                          */
/* ------------------------------------------------------------------------- */

void cli_dispatch_print_help(FILE *out, const char *program) {
    if (out == NULL) {
        return;
    }
    cli_print_global_usage(out, program);
    fputs("\nCommands:\n", out);
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        fprintf(out, "  %-14s %s\n", commands[i].name,
                commands[i].summary != NULL ? commands[i].summary : "");
    }
    fputs("\nRun `stackctl --help <verb>` for verb usage.\n", out);
}

/*
 * Per-verb option tables live in the verb packages. Only launch, terminate and
 * start/stop export theirs through their `*_internal.h` seam; provision,
 * deploy and refresh-ami keep them package-private. The dispatcher renders the
 * option list where a table is exported and falls back to the synopsis
 * otherwise instead of reaching into a peer package's private globals.
 */
static const cli_option_spec *command_options(const char *verb, size_t *count) {
    if (count == NULL) {
        return NULL;
    }
    *count = 0;
    if (verb == NULL) {
        return NULL;
    }
    if (strcmp(verb, "launch") == 0) {
        *count = launch_option_count;
        return launch_option_specs;
    }
    if (strcmp(verb, "terminate") == 0) {
        *count = terminate_option_count;
        return terminate_option_specs;
    }
    if (strcmp(verb, "start") == 0 || strcmp(verb, "stop") == 0) {
        *count = startstop_option_count;
        return startstop_option_specs;
    }
    return NULL;
}

static void trim_trailing_space(char *text) {
    size_t length;

    if (text == NULL) {
        return;
    }
    length = strlen(text);
    while (length > 0) {
        char last = text[length - 1];

        if (last != '\n' && last != '\r' && last != ' ' && last != '\t') {
            break;
        }
        text[--length] = '\0';
    }
}

/*
 * VERSION resolution.
 *
 * The documented consumed-build invocation (`bazel run //deploy/aws:stackctl`
 * from a consuming workspace) runs with cwd = the consumer checkout, so the
 * committed VERSION of this repository only exists in the binary's runfiles
 * tree. Resolution therefore walks, in order:
 *
 *   1. STACKCTL_VERSION_FILE (explicit override; authoritative when set);
 *   2. Bazel runfiles: RUNFILES_DIR, argv[0].runfiles, <exe>.runfiles, each
 *      probed at `_main/VERSION`, `stackctl/VERSION`, the bzlmod canonical
 *      repo directories (`stackctl+`, `stackctl+<version>`), and
 *      binary-dir-relative ancestors;
 *   3. cwd `VERSION`;
 *   4. executable-relative `VERSION` (ancestors of the binary).
 *
 * A committed VERSION in any probed location wins over the "unknown" fallback.
 *
 * Under bzlmod an external module is materialised in runfiles under its
 * CANONICAL repo name, so a consumed build (`bazel run //deploy/aws:stackctl`
 * from a downstream workspace) has neither `_main/` nor `stackctl/` at the
 * runfiles root. The tag there lives in `stackctl+<version>/VERSION` (or
 * `stackctl+/VERSION`); because the version suffix is not knowable up front we
 * enumerate the root's entries for the `stackctl+` prefix and also derive the
 * repo directory from argv[0]/the executable when they point inside the root.
 */
#define VERSION_PATH_MAX 4096
#define VERSION_TAG_MAX 256
#define VERSION_WORKSPACE "stackctl"
#define VERSION_CANONICAL_PREFIX "stackctl+"
#define VERSION_MAX_ANCESTORS 6

static int read_tag_file(const char *path, char *buffer, size_t capacity) {
    FILE *file;

    if (path == NULL || buffer == NULL || capacity == 0) {
        return 0;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    buffer[0] = '\0';
    if (fgets(buffer, (int)capacity, file) != NULL) {
        trim_trailing_space(buffer);
    }
    fclose(file);
    return buffer[0] != '\0';
}

static int join_path(char *out, size_t capacity, const char *dir,
                     const char *leaf) {
    int written;
    size_t length;

    if (dir == NULL || leaf == NULL || dir[0] == '\0') {
        return 0;
    }
    length = strlen(dir);
    written = snprintf(out, capacity, "%s%s%s", dir,
                       dir[length - 1] == '/' ? "" : "/", leaf);
    return written >= 0 && (size_t)written < capacity;
}

static int read_version_in_dir(const char *dir, char *buffer, size_t capacity) {
    char path[VERSION_PATH_MAX];

    return join_path(path, sizeof(path), dir, "VERSION") &&
           read_tag_file(path, buffer, capacity);
}

/* Drop the last `/`-separated component; a filesystem root is left unchanged. */
static void strip_last_component(char *path) {
    char *slash = strrchr(path, '/');

    if (slash == NULL) {
        path[0] = '\0';
    } else if (slash == path) {
        path[1] = '\0';
    } else {
        *slash = '\0';
    }
}

/*
 * Walk `dir` upward as far as `stop` (inclusive), probing `<dir>/VERSION` at
 * each level. Returns quietly when `dir` is not under `stop`, so an unrelated
 * ancestor can never supply a tag.
 */
static int read_version_between(const char *dir, const char *stop, char *buffer,
                                size_t capacity) {
    char current[VERSION_PATH_MAX];
    size_t stop_length;

    if (dir == NULL || stop == NULL) {
        return 0;
    }
    stop_length = strlen(stop);
    if (strlen(dir) >= sizeof(current) ||
        strncmp(dir, stop, stop_length) != 0) {
        return 0;
    }
    snprintf(current, sizeof(current), "%s", dir);
    for (int level = 0; level <= VERSION_MAX_ANCESTORS; level++) {
        if (read_version_in_dir(current, buffer, capacity)) {
            return 1;
        }
        if (strlen(current) <= stop_length) {
            break;
        }
        strip_last_component(current);
    }
    return 0;
}

/*
 * Probe the canonical bzlmod repo directories directly beneath `root`. Their
 * names are `stackctl+` (unversioned repo) or `stackctl+<version>` (module
 * dependency), so the version suffix cannot be predicted; enumerate the root
 * instead. Ties (multiple `stackctl+*` dirs) resolve to the lexicographically
 * smallest name for deterministic output.
 */
static int read_version_from_canonical_dirs(const char *root, char *buffer,
                                            size_t capacity) {
    char best[VERSION_PATH_MAX] = {0};
    char path[VERSION_PATH_MAX];
    DIR *dir;
    struct dirent *entry;

    if (root == NULL || root[0] == '\0') {
        return 0;
    }
    dir = opendir(root);
    if (dir == NULL) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, VERSION_CANONICAL_PREFIX,
                    sizeof(VERSION_CANONICAL_PREFIX) - 1) != 0) {
            continue;
        }
        if (best[0] == '\0' || strcmp(entry->d_name, best) < 0) {
            snprintf(best, sizeof(best), "%s", entry->d_name);
        }
    }
    closedir(dir);
    if (best[0] == '\0') {
        return 0;
    }
    return join_path(path, sizeof(path), root, best) &&
           read_version_in_dir(path, buffer, capacity);
}

static int read_version_from_runfiles(const char *root, const char *exe_dir,
                                      const char *argv0, char *buffer,
                                      size_t capacity) {
    char path[VERSION_PATH_MAX];
    char argv_dir[VERSION_PATH_MAX];
    const char *const candidates[] = {"_main", VERSION_WORKSPACE};

    if (root == NULL || root[0] == '\0') {
        return 0;
    }
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (join_path(path, sizeof(path), root, candidates[i]) &&
            read_version_in_dir(path, buffer, capacity)) {
            return 1;
        }
    }
    if (read_version_from_canonical_dirs(root, buffer, capacity)) {
        return 1;
    }
    if (read_version_between(exe_dir, root, buffer, capacity)) {
        return 1;
    }
    /* Under `bazel run`, argv[0] may be the runfiles path to the binary. */
    if (argv0 != NULL && argv0[0] != '\0' &&
        strlen(argv0) < sizeof(argv_dir)) {
        snprintf(argv_dir, sizeof(argv_dir), "%s", argv0);
        strip_last_component(argv_dir);
        if (read_version_between(argv_dir, root, buffer, capacity)) {
            return 1;
        }
    }
    return 0;
}

static int read_version_upward(const char *dir, char *buffer, size_t capacity) {
    char current[VERSION_PATH_MAX];

    if (dir == NULL || dir[0] == '\0' || strlen(dir) >= sizeof(current)) {
        return 0;
    }
    snprintf(current, sizeof(current), "%s", dir);
    for (int level = 0; level <= VERSION_MAX_ANCESTORS; level++) {
        if (read_version_in_dir(current, buffer, capacity)) {
            return 1;
        }
        if (current[0] == '\0' || strcmp(current, "/") == 0) {
            break;
        }
        strip_last_component(current);
    }
    return 0;
}

/* Resolve the running executable from /proc, falling back to an absolute argv[0]. */
static int executable_path(const char *argv0, char *out, size_t capacity) {
#ifdef __linux__
    ssize_t written = readlink("/proc/self/exe", out, capacity - 1);

    if (written > 0) {
        out[written] = '\0';
        return 1;
    }
#endif
    if (argv0 == NULL || argv0[0] == '\0' || strchr(argv0, '/') == NULL ||
        strlen(argv0) >= capacity) {
        return 0;
    }
    snprintf(out, capacity, "%s", argv0);
    return 1;
}

static void parent_dir(char *path) {
    char *slash = strrchr(path, '/');

    if (slash == NULL) {
        path[0] = '\0';
    } else if (slash == path) {
        path[1] = '\0';
    } else {
        *slash = '\0';
    }
}

static const char *resolve_version_tag(const char *argv0, char *buffer,
                                       size_t capacity) {
    const char *override = getenv(CLI_DISPATCH_VERSION_ENV);
    const char *runfiles_dir = getenv("RUNFILES_DIR");
    char exe[VERSION_PATH_MAX];
    char exe_dir[VERSION_PATH_MAX] = {0};
    char root[VERSION_PATH_MAX];
    int have_exe;

    if (buffer == NULL || capacity == 0) {
        return "unknown";
    }
    buffer[0] = '\0';

    /* 1. Explicit override: authoritative, even when it points nowhere. */
    if (override != NULL && override[0] != '\0') {
        return read_tag_file(override, buffer, capacity) ? buffer : "unknown";
    }

    have_exe = executable_path(argv0, exe, sizeof(exe));
    if (have_exe) {
        snprintf(exe_dir, sizeof(exe_dir), "%s", exe);
        parent_dir(exe_dir);
    }

    /* 2. Bazel runfiles trees (symlink tree or unified layout). */
    if (read_version_from_runfiles(runfiles_dir, have_exe ? exe_dir : NULL,
                                   argv0, buffer, capacity)) {
        return buffer;
    }
    if (argv0 != NULL && argv0[0] != '\0') {
        snprintf(root, sizeof(root), "%s.runfiles", argv0);
        if (read_version_from_runfiles(root, have_exe ? exe_dir : NULL, argv0,
                                       buffer, capacity)) {
            return buffer;
        }
    }
    if (have_exe) {
        snprintf(root, sizeof(root), "%s.runfiles", exe);
        if (read_version_from_runfiles(root, exe_dir, argv0, buffer,
                                       capacity)) {
            return buffer;
        }
    }

    /* 3. cwd-relative VERSION (repository / packaged runs). */
    if (read_version_in_dir(".", buffer, capacity)) {
        return buffer;
    }

    /* 4. Executable-relative VERSION, for uninstalled side-by-side layouts. */
    if (have_exe && read_version_upward(exe_dir, buffer, capacity)) {
        return buffer;
    }
    return "unknown";
}

int cli_dispatch_print_version_for(FILE *out, const char *argv0) {
    char tag[VERSION_TAG_MAX];

    if (out == NULL) {
        return EINVAL;
    }
    fprintf(out, "stackctl %s (spec rev %d)\n",
            resolve_version_tag(argv0, tag, sizeof(tag)),
            CLI_DISPATCH_SPEC_REV);
    return 0;
}

int cli_dispatch_print_version(FILE *out) {
    return cli_dispatch_print_version_for(out, NULL);
}

/* ------------------------------------------------------------------------- */
/* Process pipeline                                                          */
/* ------------------------------------------------------------------------- */

int cli_dispatch_run(int argc, char **argv) {
    cli_globals globals;
    cli_ctx *ctx = NULL;
    const cli_command *command;
    const char *program;
    int rc;

    /* Must precede any output: a redirected static-musl stream would otherwise
     * buffer every progress line until the verb exits. */
    (void)cli_dispatch_unbuffer_stdio();

    rc = cli_globals_parse(argc, argv, &globals);
    if (rc != 0) {
        cli_err("stackctl: invalid command line\n");
        cli_print_global_usage(stderr, argc > 0 && argv != NULL ? argv[0]
                                                               : "stackctl");
        return CLI_EXIT_USAGE;
    }
    program = globals.program != NULL ? globals.program : "stackctl";

    if (globals.version != 0) {
        (void)cli_dispatch_print_version_for(
            stdout, argc > 0 && argv != NULL ? argv[0] : NULL);
        cli_globals_free(&globals);
        return CLI_EXIT_OK;
    }

    if (globals.help != 0) {
        command = globals.verb != NULL ? cli_dispatch_find(globals.verb) : NULL;
        if (globals.verb != NULL && command == NULL) {
            cli_err("stackctl: unknown command '%s'\n", globals.verb);
            cli_print_global_usage(stderr, program);
            cli_globals_free(&globals);
            return CLI_EXIT_USAGE;
        }
        if (command != NULL) {
            size_t option_count = 0;
            const cli_option_spec *options =
                command_options(command->name, &option_count);

            cli_print_command_usage(stdout, program, command, options,
                                    option_count);
        } else {
            cli_dispatch_print_help(stdout, program);
        }
        cli_globals_free(&globals);
        return CLI_EXIT_OK;
    }

    if (globals.verb == NULL) {
        cli_err("stackctl: missing command\n");
        cli_print_global_usage(stderr, program);
        cli_globals_free(&globals);
        return CLI_EXIT_USAGE;
    }

    command = cli_dispatch_find(globals.verb);
    if (command == NULL) {
        cli_err("stackctl: unknown command '%s'\n", globals.verb);
        cli_print_global_usage(stderr, program);
        cli_globals_free(&globals);
        return CLI_EXIT_USAGE;
    }

    rc = cli_dispatch_check_globals(command, &globals, stderr);
    cli_globals_free(&globals);
    if (rc != CLI_EXIT_OK) {
        return rc;
    }

    rc = cli_ctx_init(argc, argv, &ctx);
    if (rc != 0) {
        return cli_rc_to_exit(rc);
    }

    /*
     * The first signal is routed to the verb's standard failure path. If the
     * verb still reports success after a signal was recorded, it must not be
     * reported as success: cli_dispatch_verb_exit() maps that to the frozen
     * AWS failure class (2), matching the CFN-wait rule in spec §4 without
     * synthesizing 128+signo. The second signal is immediate death in
     * cli_ctx.c.
     */
    rc = command->run(ctx);
    cli_ctx_free(ctx);
    return cli_dispatch_verb_exit(rc);
}
