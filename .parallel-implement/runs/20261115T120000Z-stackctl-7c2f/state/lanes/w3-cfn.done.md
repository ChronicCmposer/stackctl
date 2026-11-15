---
lane: w3-cfn
wave: 3
status: complete
assumptions: contract froze CFN operations but not signatures, so cfn_client (aws_ctx + per-call region) and request/result structs were designed in cfn.h; AWS CloudFormation Query protocol (form POST, XML) implemented with a small in-module XML DOM; idempotent delete_stack/delete_change_set map ENOENT to success; an empty change set is a normal result (change_count==0), while AWS "No updates are to be performed" maps to EALREADY; delete resource count is exposed via cfn_describe_stack_resources for the REVIEW_IN_PROGRESS spec rule
confidence: high
timestamp: 2026-11-15T03:42:58Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (46 targets)
- test: `bazel test //...` -> exit 0 (18/18 pass; //core/cfn:cfn_test PASSED)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck/buildifier/shellcheck/yaml/markdown)
- lint: `bazel run //tools/lint:lint-c` -> exit 0; `bazel run //tools/lint:lint-starlark` -> exit 0
- produced: core/cfn/cfn.h, core/cfn/cfn_internal.h, core/cfn/cfn.c, core/cfn/cfn_test.c, core/cfn/BUILD.bazel
- disconfirming: no live AWS call was made; exact request bodies and XML fixtures come from the fake transport, so a real endpoint/protocol change (e.g. a new required parameter) would not be caught. Waiters use aws_wait with intervals of 0 in tests; no real-time polling behavior/clock interaction was exercised. AWS error mapping is message/code-pattern based, so a reworded AWS message could fall back to EIO.
<!-- RECORD-COMPLETE -->
