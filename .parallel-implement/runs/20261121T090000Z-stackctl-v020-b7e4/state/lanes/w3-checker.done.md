---
lane: w3-checker
wave: 3
attempt: 1
status: complete
assumptions: Users/Roles/Groups attachment detection matches the operator user's logical id; bucket-handler statements remain exempt from the exact-ARN ListBucket rule as before; ArtifactReaderPolicy is checked by resource name
confidence: high
timestamp: 2026-11-21T05:05:34Z
---
## Evidence
- inbox: 1 drained
- build: bazel build //... -> exit 0
- test: bazel test //... -> exit 3 (35 pass / 7 fail; all 7 are downstream of the concurrent w3-config RELEASE_PREFIXES removal or pre-existing w4-owned CLI/e2e fixtures, none in deploy/check)
- produced: deploy/check/template_check.c, deploy/check/template_check_test.c, deploy/check/BUILD.bazel (fixture registration); acceptance `bazel test //deploy/check/...` -> exit 0
- disconfirming: did not run the 7 cross-wave failing targets to green (outside globs); did not exercise long-form Fn::Sub/Fn::If Resource shapes for the new S3 scope rules, only the short-form fixtures
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
