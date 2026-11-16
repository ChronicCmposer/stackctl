"""Per-target cppcheck aspect for //tools/lint.

`bazel build --config=lint-c //...` attaches this aspect to every C/C++
target in the build graph and runs one cppcheck action per target, so the
checks execute in parallel and cache independently. This replaces the old
serial `bazel run //tools/lint:lint-c` workspace walk for C sources.

Hermeticity note: the linter itself (cppcheck) and its `cfg/` library
definitions come from the sha256-pinned `@cppcheck` repository, and the
suppressions file is a tracked source input. The action uses `run_shell`
purely for host glue (`mktemp`/`cp`/`basename`) — the same accepted
host-touchpoint class as the previous `lint.sh` driver; nothing is resolved
from `PATH` as a linter.
"""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

_CHECKED_EXTENSIONS = (".c", ".h", ".cc", ".cpp", ".hpp")

def _shell_quote(value):
    """Return a POSIX single-quoted shell word for value."""
    return "'" + value.replace("'", "'\\''") + "'"

def _is_checked(file):
    """Whether a file is one cppcheck should inspect."""
    for extension in _CHECKED_EXTENSIONS:
        if file.basename.endswith(extension):
            return True
    return False

def _collect_sources(ctx):
    """Collect the target's own C/C++ sources and headers to check.

    Only this target's `srcs` and `hdrs` are *checked* — exactly the file
    universe of the old workspace glob for the files that participate in the
    build graph. `DefaultInfo.files` expands globs/filegroups and FileSets.
    """
    seen = {}
    sources = []
    for attribute_name in ("srcs", "hdrs"):
        entries = getattr(ctx.rule.attr, attribute_name, [])
        if entries == None:
            continue
        for entry in entries:
            if DefaultInfo not in entry:
                continue
            for file in entry[DefaultInfo].files.to_list():
                if _is_checked(file) and file.path not in seen:
                    seen[file.path] = True
                    sources.append(file)
    return sources

def _collect_parse_inputs(target):
    """Headers cppcheck must be able to read to resolve `#include`s.

    These are *not* checked; they only need to exist in the action sandbox.
    The target's transitive compilation headers cover its own and its deps'
    headers, mirroring the old driver's whole-workspace view for parsing.
    """
    if CcInfo not in target:
        return []
    return target[CcInfo].compilation_context.headers.to_list()

def _cppcheck_aspect_impl(target, ctx):
    sources = _collect_sources(ctx)
    if not sources:
        return []

    stamp = ctx.actions.declare_file(ctx.label.name + ".cppcheck.ok")
    cppcheck = ctx.executable._cppcheck
    cfg_files = ctx.attr._cfg[DefaultInfo].files.to_list()
    suppressions = ctx.file._suppressions
    parse_inputs = _collect_parse_inputs(target)

    cfg_words = " ".join([_shell_quote(file.path) for file in cfg_files])
    source_words = " ".join([_shell_quote(file.path) for file in sources])

    command = """\
set -euo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp {cppcheck} "$tmp/cppcheck"
chmod +x "$tmp/cppcheck"
mkdir -p "$tmp/cfg"
for cfg in {cfg_files}; do
    cp "$cfg" "$tmp/cfg/$(basename "$cfg")"
done
"$tmp/cppcheck" \\
    --quiet \\
    --error-exitcode=1 \\
    --enable=warning,performance,portability \\
    --inline-suppr \\
    --suppressions-list={suppressions} \\
    {sources}
printf '%s\\n' {sources} > {stamp}
printf 'OK\\n' >> {stamp}
""".format(
        cfg_files = cfg_words,
        cppcheck = _shell_quote(cppcheck.path),
        sources = source_words,
        stamp = _shell_quote(stamp.path),
        suppressions = _shell_quote(suppressions.path),
    )

    ctx.actions.run_shell(
        command = command,
        inputs = sources + parse_inputs + [suppressions],
        mnemonic = "Cppcheck",
        outputs = [stamp],
        progress_message = "Running cppcheck on %s" % ctx.label,
        tools = [cppcheck] + cfg_files,
    )

    return [OutputGroupInfo(lint = depset([stamp]))]

cppcheck_aspect = aspect(
    implementation = _cppcheck_aspect_impl,
    attr_aspects = [],
    attrs = {
        "_cfg": attr.label(default = Label("@cppcheck//:cfg")),
        "_cppcheck": attr.label(
            default = Label("@cppcheck//:cppcheck"),
            executable = True,
            cfg = "exec",
        ),
        "_suppressions": attr.label(
            default = Label("//:.cppcheck-suppressions"),
            allow_single_file = True,
        ),
    },
    required_providers = [[CcInfo]],
)
