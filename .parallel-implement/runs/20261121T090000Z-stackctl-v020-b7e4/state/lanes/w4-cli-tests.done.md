---
lane: w4-cli-tests
wave: 4
attempt: 1
status: complete
assumptions: non-empty RELEASE_PREFIXES implied CI-enabled, so fixtures use ENABLE_CI_USER=true
confidence: high
timestamp: 2026-11-21T07:00:21Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (86 targets, Build completed successfully)
- test: `bazel test //core/cli/common:cli_ctx_test //core/cli/deploy:deploy_test //core/cli/refresh_ami:refresh_ami_test --test_output=errors --nocache_test_results` -> exit 0, 3 tests pass (RED baseline before fix: exit 3)
- test: `bazel test //...` -> exit 3; 38 pass, 4 fail only in tests/** (w4-e2e scope) due to RELEASE_PREFIXES fixtures: //tests/cli:binary_verb_test, //tests/cli:guide_examples_test, //tests/contract:contract_test, //tests/e2e:stack_test
- produced: core/cli/common/cli_ctx_test.c; core/cli/deploy/deploy_test.c; core/cli/refresh_ami/refresh_ami_test.c
- disconfirming: did not touch tests/** (owned by w4-e2e); full-suite red there is expected until that lane lands. No ReleasePrefixes output assertion was present in the globs to remove (grep clean).
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
