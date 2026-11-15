---
lane: w3-cliapi
wave: 3
status: complete
assumptions: Bazel package boundary forced a symlink export: no BUILD exists at core/cli and creating one is outside lane globs, so core/cli/common is the package, core/cli/common/cli.h is a symlink to the canonical core/cli/cli.h, and the library exposes it as "cli.h" via strip_include_prefix; wave-4/5 must depend on //core/cli/common:cli and #include "cli.h"; --lock-timeout defaults to -1 (wait forever) per the spec's "waits with timeout" wording; duplicate non-repeatable value options are EINVAL while repeated boolean flags are idempotent and short-option bundling is rejected; globals are accepted before or after the verb and removed from the verb argv; cli_rc_to_exit maps EINVAL/ENOENT/ETIMEDOUT/EACCES/EPERM/ENOMEM to exit 1 and other errno-style codes to exit 2
confidence: high
timestamp: 2026-11-15T04:03:24Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (52 targets)
- build: `bazel test //...` -> exit 0 (22 tests pass)
- test: `bazel test //core/cli/common:all` -> exit 0 (cli_args_test, cli_output_test, cli_ctx_test)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 84 C files, buildifier 24 Starlark files, shellcheck, yaml_check, markdown_check)
- lint: `bazel run //tools/lint:lint-c` -> exit 0
- lint: `bazel run //tools/lint:lint-starlark` -> exit 0
- produced: core/cli/cli.h
- produced: core/cli/common/BUILD.bazel
- produced: core/cli/common/cli.h (symlink -> ../cli.h)
- produced: core/cli/common/cli_args.c, cli_output.c, cli_ctx.c
- produced: core/cli/common/cli_args_test.c, cli_output_test.c, cli_ctx_test.c
- disconfirming: the interactive TTY y/N branch was tested through cli_confirm_stream with injected streams, not a real PTY; the second-signal immediate-death path is implemented but not exercised (it would kill the test harness); real verb/AWS behavior is wave 4; the include convention is a cross-wave integration risk only if a later lane uses a parent-relative include instead of the exported "cli.h".
<!-- RECORD-COMPLETE -->
