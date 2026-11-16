#!/usr/bin/env bash
#
# lint.sh — hermetic lint driver for //tools/lint.
#
# Each tool path is passed by Bazel through $(rootpath ...) in the sh_binary
# `args` attribute, so the tools themselves are always the Bazel-fetched,
# sha256-pinned artifacts (see MODULE.bazel) and never host-installed copies.
#
# C sources are not handled here: cppcheck runs as a per-target Bazel aspect
# (tools/lint/cppcheck_aspect.bzl) via `bazel build --config=lint-c //...`, so
# each target is checked in parallel and cached independently.
#
# The workspace source tree is discovered under BUILD_WORKSPACE_DIRECTORY (set
# by `bazel run`). Vendored upstream sources live in Bazel external repositories
# and are therefore never part of the workspace walk; only our overlay files in
# third_party/ are linted. .parallel-implement/ and Bazel output symlinks are
# pruned.
#
# Exit codes: 0 clean, non-zero on any violation or tool/IO error.

set -euo pipefail

mode=""
buildifier_tool=""
shellcheck_tool=""
yaml_check_tool=""
markdown_check_tool=""

for argument in "$@"; do
    case "$argument" in
        --mode=*) mode="${argument#*=}" ;;
        --buildifier=*) buildifier_tool="${argument#*=}" ;;
        --shellcheck=*) shellcheck_tool="${argument#*=}" ;;
        --yaml-check=*) yaml_check_tool="${argument#*=}" ;;
        --markdown-check=*) markdown_check_tool="${argument#*=}" ;;
        *)
            printf 'lint: unknown argument: %s\n' "$argument" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$mode" ]]; then
    printf 'lint: --mode is required\n' >&2
    exit 2
fi

resolve_tool() {
    local path="$1"
    local stripped="${path#../}"
    local base
    local candidate

    [[ -n "$path" ]] || return 1
    if [[ -x "$path" ]]; then
        printf '%s\n' "$path"
        return 0
    fi

    for base in "${RUNFILES_DIR:-}" "$0.runfiles" "${TEST_SRCDIR:-}/${TEST_WORKSPACE:-}"; do
        [[ -n "$base" ]] || continue
        for candidate in "$base/$path" "$base/$stripped"; do
            if [[ -x "$candidate" ]]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
    done

    return 1
}

find_root() {
    if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
        printf '%s\n' "$BUILD_WORKSPACE_DIRECTORY"
    elif [[ -n "${TEST_SRCDIR:-}" && -n "${TEST_WORKSPACE:-}" ]]; then
        printf '%s\n' "$TEST_SRCDIR/$TEST_WORKSPACE"
    else
        pwd
    fi
}

collect() {
    local root="$1"
    shift
    local -a name_expr=()
    local pattern

    for pattern in "$@"; do
        if (( ${#name_expr[@]} > 0 )); then
            name_expr+=(-o)
        fi
        name_expr+=(-name "$pattern")
    done

    find "$root" \
        \( -name .git -o -name .parallel-implement -o -name 'bazel-*' \) -prune -o \
        -type f \( "${name_expr[@]}" \) -print
}

load_files() {
    local root="$1"
    shift
    local path
    files=()
    while IFS= read -r path; do
        [[ -n "$path" ]] && files+=("$path")
    done < <(collect "$root" "$@")
}

require_tool() {
    local label="$1"
    local value="$2"
    if ! resolved="$(resolve_tool "$value")"; then
        printf 'lint: %s tool not found (path: %s)\n' "$label" "$value" >&2
        return 1
    fi
    printf '%s\n' "$resolved"
}

run_starlark() {
    local tool
    tool="$(require_tool buildifier "$buildifier_tool")" || return 2
    load_files "$(find_root)" 'BUILD' 'BUILD.bazel' 'MODULE.bazel' '*.bzl'
    if (( ${#files[@]} == 0 )); then
        printf 'lint-starlark: no Starlark files found\n'
        return 0
    fi
    printf 'lint-starlark: %d file(s) via buildifier\n' "${#files[@]}"
    "$tool" -mode=check -lint=warn -warnings=all "${files[@]}"
}

run_shell() {
    local tool
    tool="$(require_tool shellcheck "$shellcheck_tool")" || return 2
    load_files "$(find_root)" '*.sh' '*.bash'
    if (( ${#files[@]} == 0 )); then
        printf 'lint-shell: no shell scripts found\n'
        return 0
    fi
    printf 'lint-shell: %d file(s) via shellcheck\n' "${#files[@]}"
    "$tool" --severity=warning --shell=bash "${files[@]}"
}

run_yaml() {
    local tool
    tool="$(require_tool yaml_check "$yaml_check_tool")" || return 2
    load_files "$(find_root)" '*.yaml' '*.yml'
    if (( ${#files[@]} == 0 )); then
        printf 'lint-yaml: no YAML files found\n'
        return 0
    fi
    printf 'lint-yaml: %d file(s) via yaml_check\n' "${#files[@]}"
    "$tool" "${files[@]}"
}

run_markdown() {
    local tool
    tool="$(require_tool markdown_check "$markdown_check_tool")" || return 2
    load_files "$(find_root)" '*.md'
    if (( ${#files[@]} == 0 )); then
        printf 'lint-markdown: no Markdown files found\n'
        return 0
    fi
    printf 'lint-markdown: %d file(s) via markdown_check\n' "${#files[@]}"
    "$tool" "${files[@]}"
}

run_all() {
    local status=0
    run_starlark || status=$?
    run_shell || status=$?
    run_yaml || status=$?
    run_markdown || status=$?
    return "$status"
}

case "$mode" in
    starlark) run_starlark ;;
    shell) run_shell ;;
    yaml) run_yaml ;;
    markdown) run_markdown ;;
    all) run_all ;;
    *)
        printf 'lint: unknown mode: %s\n' "$mode" >&2
        exit 2
        ;;
esac
