#!/usr/bin/env bash
#
# cli_invocation_test.sh — smoke-test the built `stackctl` binary's
# no-project surface: no-argument usage failure, unknown command failure,
# and the help/version success paths. The binary path is injected by Bazel.
set -euo pipefail

binary="${1:?usage: cli_invocation_test.sh <stackctl-binary>}"

if "$binary" >/dev/null 2>&1; then
    printf 'no-argument invocation unexpectedly succeeded\n' >&2
    exit 1
fi
if "$binary" frobnicate >/dev/null 2>&1; then
    printf 'unknown-command invocation unexpectedly succeeded\n' >&2
    exit 1
fi
"$binary" --help >/dev/null
"$binary" --version >/dev/null
printf 'cli_invocation_test: ok\n'
