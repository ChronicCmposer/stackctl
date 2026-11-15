# AGENTS.md — contributor and agent guide for stackctl

This repository is bzlmod-only and builds with the hermetic zig-cc musl toolchain
pinned in `MODULE.bazel`. All build, test, and lint commands run through Bazel;
nothing depends on a host-installed compiler, linter, or test runner (CONTRACT
Amendment 4).

Lint is part of the gate at every verification step (CONTRACT Amendment 3). The
aggregate target `//tools/lint:lint` discovers files by glob over the workspace
(pruning `.git/`, `.parallel-implement/`, and `bazel-*` output symlinks), so new
modules are covered automatically without editing a file list. Vendored upstream
sources come from Bazel external repositories and are never linted; only our
overlay files under `third_party/` are.

Tooling is fetched and pinned by `MODULE.bazel`: cppcheck 2.22.0 (built from its
sha256-pinned release source with the hermetic C++ toolchain), buildifier
v10.2.0, and shellcheck v0.11.0 (pinned release binaries). The Markdown and YAML
checkers are small in-repo C programs (`tools/lint/markdown_check.c`,
`tools/lint/yaml_check.c`) compiled hermetically; they substitute for
markdownlint-cli2 and yamllint so no Node or Python toolchain is required. Root
configuration dotfiles (`.shellcheckrc`, `.markdownlint.json`, `.yamllint`,
`.cppcheck-suppressions`) record the conservative defaults these checks enforce.

```build-policy
[verify]
build = "bazel build //..."
test = "bazel test //..."
lint = "bazel run //tools/lint:lint"
```

Run the individual linters while iterating:

```bash
bazel run //tools/lint:lint-c          # cppcheck over C sources and headers
bazel run //tools/lint:lint-starlark   # buildifier over BUILD/MODULE/*.bzl
bazel run //tools/lint:lint-shell      # shellcheck over shell scripts
bazel run //tools/lint:lint-yaml       # yaml_check over *.yaml/*.yml
bazel run //tools/lint:lint-markdown   # markdown_check over *.md
```

The block above is the authoritative command list; do not duplicate or reword it
elsewhere in this file.

## Repository layout

```text
core/
  config/          .env parsing, validation, repo-root resolution
  crypto/          SHA-256, HMAC-SHA256, SigV4
  ini/             ~/.aws/credentials upsert
  state/           XDG state dir, project lock, bindings, launch/release/audit records
  ssh/             ssh(1)/scp(1) argv builder and sentinel-aware exec
  knownhosts/      dedicated host-key store
  aws/             single AWS HTTP seam (curl + SigV4, retries, waiters)
  cfn/ ec2/ s3/    request builders and response parsers over core/aws
  ssm/ iam/
  ddns/            Namecheap DDNS update over curl (its own seam)
  dns/             authoritative-nameserver queries via c-ares
  cli/
    cli.h          frozen CLI substrate (exit codes, cli_ctx, args, output)
    common/        context construction, argument parsing, output helpers
    <verb>/        one directory per verb group
    dispatch/      frozen verb table and the single cc_binary target
  main.c           thin entry point
deploy/            canonical CFN templates and the structural template checker
tests/             integration, contract and link-seam tests
third_party/       BUILD overlays for vendored dependencies
tools/lint/        hermetic lint drivers and in-repo Markdown/YAML checkers
```

Each module directory owns its own `BUILD.bazel`, defining a `cc_library` named
after the module plus colocated `cc_test` targets. Keep new targets colocated with
the code they build.

## Code philosophy

- Backend and logic code follows the **code-philosophy** skill (The 5 Laws of
  Elegant Defense). Load it before implementing and verify against its checklist.
- UI/frontend philosophy does not apply: this repository has no user interface.
- Error model: library functions return `0` on success or a non-zero errno-style
  code, with results in out-params. Only CLI verb layers map failures to process
  exit codes.
- Allocation: prefer caller-provided buffers; heap returns use an out-param and an
  explicit `_free()` destructor. No global mutable state except the state module's
  locked store.
- All stackctl-authored C code uses **C23** (`-std=gnu23`, or `-std=c23` when no
  extensions are needed). Vendored upstream sources keep their own flags.
- Public symbols are prefixed with the module name (`config_`, `crypto_`, `sigv4_`,
  `aws_`, `cfn_`, `ec2_`, `s3_`, `ssm_`, `iam_`, `ddns_`, `dns_`, `ini_`,
  `state_`, `sshc_`, `kh_`, `cli_`).
- stdout is reserved for CLI output, including the single `--json` document.
  Diagnostics, warnings and prompts go to stderr. Errors never go to stdout.
- JSON uses yyjson only.

## Architecture rules

- `config` is the only module that reads files at startup; downstream modules take
  typed values.
- `core/aws` is the single AWS-API seam. Only `cfn`, `ec2`, `s3`, `ssm` and `iam`
  build requests over it.
- The only other network users are `ddns` (its own curl request), `dns` (c-ares),
  and `status`'s single `IP_ECHO_URL` fetch. A link-time test asserts that no other
  translation unit references socket symbols.
- `ssh` never links a libssh; it execs OpenSSH with a controlled argv and the
  dedicated known-hosts store.
- `state` owns all persistence and the coarse per-project-per-region lock. `status`
  is the only lockless verb.
- The canonical CFN templates must satisfy the template contract; the same checker
  validates `TEMPLATE_OVERRIDE` at deploy time and the canonical templates in
  tests.

## Working conventions

- **TDD.** Build each behavior RED → GREEN → REFACTOR. Write the failing test
  first, make it pass with the minimal change, then refactor with the suite green.
  A refactor must not change behavior.
- **Lint.** Lint must pass for the files you touch. Fix violations in your own
  sources; do not edit the orchestrator-owned lint configuration dotfiles.
- **Version.** `VERSION` is the single source of truth for the release identity.
  `MODULE.bazel` mirrors it because bzlmod cannot read a workspace file while
  evaluating the module; the hermetic `//:version_consistency_test` fails
  `bazel test //...` if the two drift.
- **Hermetic tools.** Never rely on host-installed tools for a required gate.
  Invoke everything through Bazel, as the build policy states.
- **Vendoring.** Dependencies are sha256-pinned `http_archive`s built from source. The
  one sanctioned exception is the lint tooling: buildifier and shellcheck are pinned,
  sha256-verified prebuilt release binaries fetched through Bazel (per-CPU `select()`),
  never host-installed. Update pins deliberately; add no other host-built artifacts or
  prebuilt downloads.
- **Secrets.** The live `deploy/aws/.env` is machine-local and gitignored. Never
  commit credentials, private keys or the DDNS password. Audit logs redact secrets.
- **Config accuracy.** Config keys live in the `core/config` allowlist; do not
  invent keys. CLI flags live in the per-verb option tables; do not invent flags.

## Documentation

- `README.md` is the operator and developer surface: build, configuration, all
  eight verbs, exit codes, DDNS/SSM setup, SSH behavior and troubleshooting.
- Keep documentation in sync with the code. Derive commands, flags and config keys
  from the sources and the design specification; never document unverified
  behavior.
- Markdown must satisfy `markdown_check`: no tabs, LF endings, ATX headings with a
  space after the `#` run, prose lines at most 120 columns, and a trailing newline.
