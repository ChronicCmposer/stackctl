---
lane: w3-provision
wave: 3
attempt: 1
status: complete
assumptions: refusal maps to CLI_EXIT_USAGE, matching the existing non-interactive --yes refusal
confidence: high
timestamp: 2026-11-21T05:02:32Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- build: `bazel build //core/cli/provision:provision //core/cli/provision:provision_test` -> exit 0
- build: `bazel build --config=lint-c //core/cli/provision:provision //core/cli/provision:provision_test` -> exit 0
- test: `bazel test //core/cli/provision:provision_test --nocache_test_results` -> exit 0 (PASSED)
- test: `bazel test //...` -> exit 3 (35 passed, 7 failed); every failure is the `RELEASE_PREFIXES was removed in v0.2.0` hard error raised against fixtures in core/cli/{common,deploy,refresh_ami} and tests/{cli,contract,e2e}, which the contract assigns to w4-cli-tests/w4-e2e
- produced: core/cli/provision/provision.c, core/cli/provision/provision_internal.h, core/cli/provision/provision_test.c, logs/w3-provision.md
- disconfirming: --delete-ci-user behavior is exercised through provision_run with a fake vtable, not through the real dispatch argv; no live-AWS run; the //... failures are out of this lane's globs
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
