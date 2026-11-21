---
lane: w4-e2e
wave: 4
attempt: 1
status: complete
assumptions: all former RELEASE_PREFIXES=releases/ fixtures treated as ENABLE_CI_USER=true because the key was non-empty; tests/** contains no template/JSON golden encoding the releases-only grant model
confidence: high
timestamp: 2026-11-21T07:01:07Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- test: `bazel test //tests/cli:binary_verb_test //tests/cli:guide_examples_test //tests/contract:contract_test //tests/e2e:stack_test --test_output=errors --nocache_test_results` -> exit 0 (4/4 pass, red before change)
- test: `bazel test //tests/... --test_output=errors --nocache_test_results` -> exit 0 (7/7 pass)
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 (42/42 pass)
- produced: tests/e2e/stack_test.c, tests/contract/contract_test.c, tests/cli/guide_examples_test.c, tests/cli/binary_verb_test.c, tests/cli/cli_contract_test.sh
- disconfirming: did not touch core/, deploy/, docs, VERSION, MODULE.bazel; template/JSON goldens for the bucket-wide grant live outside tests/** (deploy/check testdata), so none changed here.
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
