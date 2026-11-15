/*
 * cli.h — shared CLI substrate for stackctl (CONTRACT.md §core/cli, spec §4).
 *
 * This header is the frozen interface consumed by the wave-4 verb lanes
 * (`cli_cmd_<verb>` implementations) and by the wave-5 dispatcher
 * (`core/main.c` + `core/cli/dispatch/`). It owns:
 *
 *   - the frozen exit-code constants (spec §4),
 *   - the opaque `cli_ctx` carrying parsed globals, config and state,
 *   - deterministic argv parsing helpers (`cli_args_parse`),
 *   - global-flag parsing (`cli_globals_parse`),
 *   - command/verb registration structures and lookup,
 *   - stdout/stderr, table and JSON output helpers,
 *   - confirmation / non-interactive behaviour,
 *   - secret redaction for diagnostics and audit strings,
 *   - usage/error rendering and exit-code classification.
 *
 * Error model (CONTRACT.md): helper functions return 0 on success and a
 * non-zero errno-style code otherwise; CLI-facing failures are reported with
 * `cli_fail()`, whose return value is the frozen process exit code.
 *
 * Bazel consumers depend on `//core/cli/common:cli` and include `"cli.h"`; the
 * library exports this header through a virtual include directory so verb and
 * dispatch packages need no parent-package source labels.
 *
 * Stream discipline (spec §4): diagnostics and prompts go to stderr; stdout is
 * reserved for verb output, including the single JSON document emitted under
 * `--json`. Errors are never written to stdout, so stdout JSON stays parseable.
 */

#ifndef STACKCTL_CLI_CLI_H
#define STACKCTL_CLI_CLI_H

#include <stddef.h>
#include <stdio.h>

#include "core/config/config.h"
#include "core/state/state.h"

/* Forward declaration: JSON emission takes a yyjson mutable document. */
struct yyjson_mut_doc;

/* Forward declaration: the identity guard operates on an AWS client. */
struct aws_ctx;

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Exit codes (frozen; spec §4)                                              */
/* ------------------------------------------------------------------------- */

typedef enum cli_exit_code {
    CLI_EXIT_OK = 0,        /* success */
    CLI_EXIT_USAGE = 1,     /* usage / config error, incl. lock-timeout */
    CLI_EXIT_AWS = 2,       /* AWS API error after retries */
    CLI_EXIT_VERIFY = 3,    /* verification failure (sha, identity, provenance) */
    CLI_EXIT_LAUNCH = 4,    /* launch failed and the instance was terminated */
    CLI_EXIT_CLEANUP = 5,   /* teardown/cleanup incomplete */
    CLI_EXIT_FRESHNESS = 6, /* deployment artifact stale or unbuilt */
    CLI_EXIT_SSH = 7        /* SSH transport failure */
} cli_exit_code;

/*
 * Map an errno-style return code from a library call to the frozen CLI exit
 * code. Usage/config/lock failures map to CLI_EXIT_USAGE; everything else is
 * treated as an AWS/transport-class failure (CLI_EXIT_AWS). Verb layers with a
 * more specific classification (verification, SSH, freshness) use the explicit
 * enum value instead.
 */
int cli_rc_to_exit(int rc);

/* ------------------------------------------------------------------------- */
/* Option parsing                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Declaration of one long/short option a verb accepts.
 *
 *   name        long name without the leading "--" (required).
 *   short_name  optional single-character short name, or 0.
 *   takes_value non-zero when the option requires a value.
 *   repeatable  non-zero when the option may occur more than once; every
 *               value is retained (in order) in cli_option_value.values.
 *   metavar     value placeholder for usage rendering (e.g. "<sec>").
 *   help        one-line help text for usage rendering.
 *
 * Parsing is deterministic: `--name=value` and `--name value` are accepted for
 * value options; a second occurrence of a non-repeatable option is EINVAL; an
 * empty `--name=` value is EINVAL; unknown options are EINVAL; `--` ends option
 * parsing and leaves the remainder as positionals.
 */
typedef struct cli_option_spec {
    const char *name;
    char short_name;
    int takes_value;
    int repeatable;
    const char *metavar;
    const char *help;
} cli_option_spec;

/* Result for one declared option. */
typedef struct cli_option_value {
    const char *name;
    int present;
    size_t count;            /* number of occurrences */
    const char *value;       /* last value (NULL for boolean flags) */
    const char **values;     /* all values when repeatable, else NULL */
    size_t value_count;
} cli_option_value;

/*
 * Parsed argument vector. `argv[0]` is the program/verb name; parsing starts at
 * `argv[1]`. All returned string pointers point into the caller's `argv` and
 * remain valid while it lives. The structure owns only its internal arrays and
 * must be released with cli_args_free().
 */
typedef struct cli_args {
    const cli_option_spec *specs;
    size_t spec_count;
    cli_option_value *values; /* parallel to specs */
    const char **positionals;
    size_t positional_count;
    const char *argv0;
} cli_args;

/*
 * Parse a verb argument vector against `specs`.
 *
 * Returns 0 on success, EINVAL on bad arguments / unknown option / missing
 * value / empty `--name=` / duplicate non-repeatable option, or ENOMEM. On
 * failure `out` is zeroed and owns nothing.
 */
int cli_args_parse(int argc, char **argv, const cli_option_spec *specs,
                   size_t spec_count, cli_args *out);

/* Release arrays owned by cli_args_parse(). Safe on NULL / zeroed. */
void cli_args_free(cli_args *args);

/* Return the parsed entry for `name`, or NULL when it is not declared. */
const cli_option_value *cli_args_get(const cli_args *args, const char *name);

/* Return 1 when the option is present (boolean flag or any value), else 0. */
int cli_args_flag(const cli_args *args, const char *name);

/* Return the last value for `name`, or NULL when absent/boolean. */
const char *cli_args_value(const cli_args *args, const char *name);

/* ------------------------------------------------------------------------- */
/* Global flags                                                              */
/* ------------------------------------------------------------------------- */

/*
 * Parsed global flags. Globals may appear before or after the verb; recognised
 * global options are removed from the verb argument vector. Any `--help` makes
 * `verb` optional (command help); `--version` likewise.
 */
typedef struct cli_globals {
    const char *program;        /* argv[0] (never NULL on success) */
    const char *verb;           /* first non-global positional, or NULL */
    const char *project;        /* --project value, or NULL */
    const char *region;         /* --region value, or NULL */
    int region_explicit;        /* --region was given */
    int json;                   /* --json */
    int yes;                    /* --yes / -y */
    int dry_run;                /* --dry-run */
    int lock_timeout;           /* --lock-timeout seconds; -1 = wait forever */
    int help;                   /* --help / -h */
    int version;                /* --version */
    int verb_argc;              /* verb_argv[0] is the verb name */
    char **verb_argv;           /* heap array of pointers into argv */
} cli_globals;

/*
 * Parse global flags out of a full command line.
 *
 * Returns 0, EINVAL (unknown global option before the verb, malformed value) or
 * ENOMEM. On success `out` owns `verb_argv`; release with cli_globals_free().
 */
int cli_globals_parse(int argc, char **argv, cli_globals *out);

/* Release heap arrays owned by cli_globals_parse(). Safe on NULL / zeroed. */
void cli_globals_free(cli_globals *globals);

/* ------------------------------------------------------------------------- */
/* Context                                                                   */
/* ------------------------------------------------------------------------- */

/*
 * Opaque per-invocation context: parsed globals, the loaded config, the state
 * store and (for mutating verbs) the held project lock.
 */
typedef struct cli_ctx cli_ctx;

/*
 * Parse the command line, load + validate the project config, open the state
 * store, and acquire the coarse project lock according to the verb's policy
 * (`status` and help/version are lockless; the seven mutating verbs lock).
 * Installs the first-signal/second-signal SIGINT/SIGTERM handlers.
 *
 * For `--help`/`--version` no project, config, state or lock is required.
 * Returns 0 on success, else EINVAL (usage/config), ETIMEDOUT (lock expiry), or
 * another errno-style code. The caller must cli_ctx_free() on success.
 */
int cli_ctx_init(int argc, char **argv, cli_ctx **out);

/* Release a context, unlocking and freeing config/state as needed. Safe on NULL. */
void cli_ctx_free(cli_ctx *ctx);

/* Accessors; owned by the context and valid until cli_ctx_free(). */
const char *cli_ctx_program(const cli_ctx *ctx);
const char *cli_ctx_verb(const cli_ctx *ctx);
const stackctl_config *cli_ctx_config(const cli_ctx *ctx);
state_store *cli_ctx_state(const cli_ctx *ctx);
int cli_ctx_json(const cli_ctx *ctx);
int cli_ctx_yes(const cli_ctx *ctx);
int cli_ctx_dry_run(const cli_ctx *ctx);
int cli_ctx_lock_timeout(const cli_ctx *ctx);

/* Verb argument vector: argv[0] is the verb name; parse with cli_args_parse(). */
int cli_ctx_verb_argc(const cli_ctx *ctx);
char **cli_ctx_verb_argv(const cli_ctx *ctx);

/*
 * Convenience wrapper: cli_args_parse() over the context's verb arguments.
 * Returns 0 / EINVAL / ENOMEM exactly as cli_args_parse().
 */
int cli_ctx_parse_args(const cli_ctx *ctx, const cli_option_spec *specs,
                       size_t spec_count, cli_args *out);

/* ------------------------------------------------------------------------- */
/* Verb registration                                                         */
/* ------------------------------------------------------------------------- */

/*
 * One verb registration entry. Wave-5 dispatch builds a static table of these
 * and uses cli_command_find(); wave-4 supplies the `run` implementations.
 */
typedef struct cli_command {
    const char *name;       /* "provision" */
    const char *summary;    /* one-line description */
    const char *usage;      /* e.g. "provision [--rotate] [--rotate-ci]" */
    int (*run)(cli_ctx *);  /* cli_cmd_<verb> */
    int mutates;            /* non-zero when the verb must hold the project lock */
    int supports_dry_run;   /* non-zero when --dry-run is meaningful */
} cli_command;

/* Look up a command by name; returns NULL when absent. */
const cli_command *cli_command_find(const cli_command *commands, size_t count,
                                    const char *name);

/* Non-zero when `verb` is one of the eight frozen verb names. */
int cli_verb_known(const char *verb);

/* Non-zero when `verb` mutates and therefore requires the project lock. */
int cli_verb_mutates(const char *verb);

/* Frozen verb names, NULL-terminated; `*count` (optional) receives the count. */
const char *const *cli_verb_names(size_t *count);

/* Frozen verb entry points (implemented by the wave-4 verb lanes). */
int cli_cmd_provision(cli_ctx *ctx);
int cli_cmd_deploy(cli_ctx *ctx);
int cli_cmd_refresh_ami(cli_ctx *ctx);
int cli_cmd_launch(cli_ctx *ctx);
int cli_cmd_terminate(cli_ctx *ctx);
int cli_cmd_status(cli_ctx *ctx);
int cli_cmd_start(cli_ctx *ctx);
int cli_cmd_stop(cli_ctx *ctx);

/* ------------------------------------------------------------------------- */
/* Output                                                                    */
/* ------------------------------------------------------------------------- */

/* printf-style output to stdout (verb output only). */
void cli_out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* printf-style output to stderr (diagnostics only). */
void cli_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* printf-style warning to stderr, prefixed with "stackctl: warning: ". */
void cli_warn(cli_ctx *ctx, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/*
 * Report a CLI failure on stderr as "stackctl: <message>" and return `code`.
 * Errors always go to stderr, even under --json, so stdout stays parseable.
 * Typical use: `return cli_fail(ctx, CLI_EXIT_USAGE, "missing --project");`
 */
int cli_fail(cli_ctx *ctx, int code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Aligned table rendering (plain-text output; not used for --json). */
typedef struct cli_table {
    const char *const *headers; /* header_count column titles */
    size_t header_count;
    const char *const *cells; /* row-major, row_count * header_count; NULL = "" */
    size_t row_count;
} cli_table;

/* Write an aligned table. Returns 0, EINVAL on inconsistent arguments. */
int cli_table_write(FILE *out, const cli_table *table);

/*
 * Emit a yyjson mutable document as pretty JSON followed by a newline.
 * The document stays owned by the caller. Returns 0, EINVAL (bad arguments) or
 * ENOMEM. `cli_json_emit()` writes to stdout.
 */
int cli_json_write(FILE *out, struct yyjson_mut_doc *doc);
int cli_json_emit(struct yyjson_mut_doc *doc);

/* ------------------------------------------------------------------------- */
/* Confirmation & TTY                                                        */
/* ------------------------------------------------------------------------- */

#define CLI_CONFIRM_YES 1
#define CLI_CONFIRM_NO 0
#define CLI_CONFIRM_NONINTERACTIVE (-1) /* non-TTY without --yes */
#define CLI_CONFIRM_EOF (-2)            /* interactive prompt hit EOF */

/* Non-zero when `stream` is a terminal. */
int cli_is_tty(FILE *stream);

/*
 * Decide a `apply? [y/N]` style prompt.
 *
 * `--yes` returns CLI_CONFIRM_YES without reading. A non-TTY stdin returns
 * CLI_CONFIRM_NONINTERACTIVE (callers map that to exit 1 with a message
 * suggesting --yes). On a TTY, read one line from stdin: y/Y/yes (case
 * insensitive) is YES, empty/anything else is NO, EOF is CLI_CONFIRM_EOF.
 * The prompt is written to stderr so stdout output stays clean.
 */
int cli_confirm(cli_ctx *ctx, const char *prompt);

/*
 * Lower-level confirmation used by tests: read from `in`, write the prompt to
 * `out`. When `interactive` is zero, return CLI_CONFIRM_NONINTERACTIVE without
 * reading; when `assume_yes` is non-zero, return CLI_CONFIRM_YES without
 * reading.
 */
int cli_confirm_stream(FILE *in, FILE *out, int interactive, int assume_yes,
                       const char *prompt);

/* ------------------------------------------------------------------------- */
/* Secret redaction                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Render `argv` as a single space-separated diagnostic/audit string with secret
 * values replaced by `<redacted>`. Secret-bearing options are long options
 * whose name contains password/secret/token (case-insensitive), both
 * `--name=value` and `--name value` forms, plus env-style `KEY=value` tokens
 * whose key contains PASSWORD/SECRET/TOKEN. Never returns secrets.
 *
 * Returns 0 on success, EINVAL on bad arguments, or ERANGE when `out` is too
 * small (out is never left unterminated on failure).
 */
int cli_redact_args(const char *const *argv, size_t argc, char *out,
                    size_t out_size);

/* ------------------------------------------------------------------------- */
/* Usage                                                                     */
/* ------------------------------------------------------------------------- */

/* Render the top-level usage synopsis and global flag list to `out`. */
void cli_print_global_usage(FILE *out, const char *program);

/*
 * Render per-command usage: synopsis from `command->usage`, its summary, and
 * the verb's option table. `options` may be NULL when option_count is 0.
 */
void cli_print_command_usage(FILE *out, const char *program,
                             const cli_command *command,
                             const cli_option_spec *options,
                             size_t option_count);

/* ------------------------------------------------------------------------- */
/* Identity                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Assert the caller is the project IAM user (`arn:...:user/<project>`), the
 * shared guard the identity-mutating verbs re-run before acting.
 *
 * Returns CLI_EXIT_OK (0) on an exact `:user/<project>` suffix match;
 * CLI_EXIT_AWS (2) when STS GetCallerIdentity fails; CLI_EXIT_VERIFY (3) when
 * the ARN does not end in the expected suffix or is an assumed-role ARN
 * (`arn:aws:sts::...:assumed-role/...`). Diagnostics go to stderr. Account-id
 * verification is intentionally out of scope (there is no configured account
 * key); this mirrors the existing per-verb guards.
 */
int cli_assert_operator_identity(struct aws_ctx *aws, const char *project);

/* ------------------------------------------------------------------------- */
/* Signals                                                                   */
/* ------------------------------------------------------------------------- */

/*
 * Install SIGINT/SIGTERM handlers (idempotent). The first signal records the
 * signal for the standard failure path; a second signal terminates immediately
 * with 128+signo (no further cleanup). Verb layers poll cli_signal_received()
 * between steps.
 */
void cli_signal_install(void);

/* Non-zero after the first SIGINT/SIGTERM was observed. */
int cli_signal_received(void);

/* The first observed signal number, or 0 when none. */
int cli_signal_number(void);

/*
 * Record that the current verb handled the first signal itself (for example,
 * mapping EINTR to its own failure path). The dispatcher then honors the verb's
 * returned exit code verbatim instead of mapping any received signal to
 * CLI_EXIT_AWS. Consumed state is cleared by cli_signal_test_reset().
 */
void cli_signal_mark_consumed(void);

/* Non-zero once cli_signal_mark_consumed() was called for this run. */
int cli_signal_consumed(void);

/*
 * Abort callback for interruptible library waits (aws_abort_fn shape): returns
 * non-zero once the first SIGINT/SIGTERM was recorded. `user` is unused.
 *
 * Verb layers install it on their AWS client with aws_set_abort_hook(), so
 * cfn/ec2 waiters built on aws_wait() stop with EINTR instead of ignoring the
 * signal until the operation completes.
 */
int cli_abort_check(void *user);

/*
 * Single-threaded test seams for the signal bookkeeping. Production signals
 * reach the same state through on_signal(); these let the dispatch tests
 * simulate "a signal was received" without raising one.
 */
void cli_signal_test_fire(int number);
void cli_signal_test_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_CLI_H */
