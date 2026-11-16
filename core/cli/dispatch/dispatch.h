/*
 * dispatch.h — top-level command dispatch for the `stackctl` binary.
 *
 * `core/main.c` is a thin shell around `cli_dispatch_run()`: that function owns
 * the deterministic CLI pipeline described by spec §4 and CONTRACT.md —
 * global-flag parsing, verb resolution against the frozen `cli_command` table,
 * top-level help/usage/version rendering, the eight `cli_cmd_*` entry points,
 * stdout/stderr discipline and frozen exit-code mapping. No verb, AWS or config
 * behaviour lives here.
 *
 * The table and helpers are exposed for the colocated test target so the
 * dispatch decisions (resolution, global-flag enforcement, exit mapping) can be
 * exercised with fakes and without a project config.
 */

#ifndef STACKCTL_CLI_DISPATCH_DISPATCH_H
#define STACKCTL_CLI_DISPATCH_DISPATCH_H

#include <stddef.h>
#include <stdio.h>

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Spec revision reported by `--version` alongside the committed VERSION tag. */
#define CLI_DISPATCH_SPEC_REV 8

/* Environment override for the VERSION file path (tests and packaged runs). */
#define CLI_DISPATCH_VERSION_ENV "STACKCTL_VERSION_FILE"

/*
 * The frozen command table: one entry per verb, in usage order. `run` points at
 * the wave-4 `cli_cmd_<verb>` implementations; `mutates` mirrors
 * `cli_verb_mutates()` and `supports_dry_run` marks the previewing verbs
 * (provision, deploy, refresh-ami).
 */
const cli_command *cli_dispatch_table(size_t *count);

/* Resolve `verb` against the table; NULL for an unknown/NULL name. */
const cli_command *cli_dispatch_find(const char *verb);

/*
 * Enforce global flags that are meaningful only for some verbs. Today that is
 * `--dry-run`, rejected with CLI_EXIT_USAGE for a verb whose
 * `supports_dry_run` is zero. Returns CLI_EXIT_OK when the flags are allowed.
 */
int cli_dispatch_check_globals(const cli_command *command,
                               const cli_globals *globals, FILE *err);

/*
 * Map a verb return value to a frozen process exit code. The named frozen
 * constants (CLI_EXIT_*) pass through unchanged, compared explicitly against
 * the enum rather than a 0..7 range; other errno-style or negative values are
 * classified with `cli_rc_to_exit()`. Verbs are audited to return only the
 * frozen constants, because those values numerically overlap the first errno
 * values and cannot be distinguished from them by value alone.
 */
int cli_dispatch_normalize_rc(int rc);

/*
 * Final exit code for a completed verb. Normalizes `verb_rc` as above, but if
 * the verb reported success while a first SIGINT/SIGTERM was recorded, reports
 * CLI_EXIT_AWS (2) instead: spec §4 makes a signal-interrupted wait a failure
 * (CloudFormation waits explicitly exit 2), never a success. A non-success
 * verb code is preserved. Never synthesizes 128+signo.
 */
int cli_dispatch_verb_exit(int verb_rc);

/*
 * Put stdout and stderr into unbuffered mode. stackctl is a statically linked
 * musl binary, so libc fully buffers redirected/piped streams and a long verb
 * looks hung until it exits. `cli_dispatch_run` calls this before any verb
 * runs; it is exposed so the colocated test can assert the observable
 * behaviour (a write reaches a pipe without an explicit flush).
 *
 * Returns 0 when both streams were switched, or EIO when either setvbuf()
 * call failed. Failure is non-fatal for the CLI: output still works, it is
 * merely buffered when the destination is not a terminal.
 */
int cli_dispatch_unbuffer_stdio(void);

/* Render top-level help (usage, command list, global flags) to `out`. */
void cli_dispatch_print_help(FILE *out, const char *program);

/*
 * Render `stackctl <version-tag> (spec rev N)` to `out`. The tag is resolved
 * from, in order: CLI_DISPATCH_VERSION_ENV, the Bazel runfiles tree
 * (`_main/VERSION`, `stackctl/VERSION`, bzlmod canonical
 * `stackctl+[<version>]/VERSION`, binary-relative), cwd `VERSION`, and finally
 * an executable-relative `VERSION`. A missing/empty file renders as `unknown`.
 * Returns 0, or EINVAL for a NULL stream.
 */
int cli_dispatch_print_version(FILE *out);

/*
 * As cli_dispatch_print_version(), but with the process's argv[0] so runfiles
 * resolution can also try `<argv[0]>.runfiles` (the layout `bazel run` uses
 * when RUNFILES_DIR is not exported). `argv0` may be NULL.
 */
int cli_dispatch_print_version_for(FILE *out, const char *argv0);

/*
 * Full process pipeline. Returns the frozen process exit code (0-7) reported by
 * the verb after its standard failure path. The first SIGINT/SIGTERM is handled
 * by the verb (spec §4); dispatch never synthesizes 128+signo because that is
 * outside the stable exit-code table. The second signal is immediate death in
 * cli_ctx.c. Never calls exit(); the caller's `main` returns this.
 */
int cli_dispatch_run(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_DISPATCH_DISPATCH_H */
