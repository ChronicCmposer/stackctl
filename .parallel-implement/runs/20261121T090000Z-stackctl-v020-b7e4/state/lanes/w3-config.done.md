---
lane: w3-config
wave: 3
attempt: 1
status: complete
assumptions: none
confidence: high
timestamp: 2026-11-21T05:01:27Z
---
## Evidence
- inbox: empty
- build: bazel build //... -> exit 0
- test: bazel test //core/config:config_test -> exit 0
- test: bazel test //... -> exit 3 (config_test green; 8 out-of-scope suites still
  fail on fixtures carrying RELEASE_PREFIXES: core/cli/common, core/cli/deploy,
  core/cli/provision, core/cli/refresh_ami, tests/cli, tests/contract,
  tests/e2e — owned by w3-provision and w4-cli-tests/w4-e2e)
- lint: bazel build --config=lint-c //core/config:config //core/config:config_test -> exit 0
- lint: bazel run //tools/lint:lint -> exit 0
- lint: bazel build --config=lint-c //... -> exit 1, external: provision.c:1016
  "no member named 'delete_ci_user' in 'struct provision_env'" (w3-provision mid-edit)
- produced: core/config/config.c; core/config/config_test.c;
  logs/w3-config.md; state/lanes/w3-config.done.md
- disconfirming: full-workspace build/lint/test cannot be green in this lane because
  out-of-scope fixtures and w3-provision edits are still in flight; only
  //core/config was verified clean. T-S4/T-S5 are covered by config_test.
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
