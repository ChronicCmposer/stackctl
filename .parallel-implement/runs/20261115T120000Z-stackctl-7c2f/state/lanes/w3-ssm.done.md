---
lane: w3-ssm
wave: 3
status: complete
assumptions: SSM is JSON-1.1, so every operation sends POST / with signed extra headers "X-Amz-Target: AmazonSSM.<Operation>" and "Content-Type: application/x-amz-json-1.1" via aws_req.extra_headers (CONTRACT Amendment 5); req.content_type is left NULL so Content-Type is emitted and signed exactly once from the extra header; unsigned_payload stays 0 so the JSON body is SHA-256 signed; the production transport calls aws_request directly and remains injectable through the ssm_transport_fn seam for tests; ssm_send_command/get_command_invocation/wait_command are exposed per the lane brief although design §4 start/stop uses SSH; ssm_put_parameter is intentionally absent because spec §3 makes the DDNS SecureString bootstrap manual and §9 states stackctl never writes SSM parameters.
confidence: high
timestamp: 2026-11-15T04:25:00Z
---
## Evidence
- inbox: 1 drained (orchestrator reply `w3-ssm-20261115T034643Z-ssm-x-amz-target-seam.md.reply.md`, disposition `done`, resolved and not rewritten)
- build: `bazel build //...` -> exit 0 (52 targets)
- test: `bazel test //...` -> exit 0 (22/22 tests, `//core/ssm:ssm_test` PASSED)
- red: `bazel test //core/ssm:ssm_test --test_output=errors` -> exit 1 (`ld.lld: error: undefined symbol: ssm_build_headers`, proving the new extra-header/header-builder tests fail before the wiring)
- green: `bazel test //core/ssm:ssm_test --test_output=errors` -> exit 0; direct run prints `all 226 checks passed` -> exit 0 (up from 188 checks on attempt 1)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 84 files, buildifier 24, shellcheck 1, yaml 8, markdown 2); focused `bazel run //tools/lint:lint-c` -> exit 0
- produced: core/ssm/ssm.h, core/ssm/ssm_internal.h, core/ssm/ssm.c, core/ssm/ssm_test.c, core/ssm/BUILD.bazel
- wiring: `ssm_build_headers` builds the two signed extra header lines; `ssm_call_api` sets `extra_headers`/`extra_header_count = 2`, `content_type = NULL`, `unsigned_payload = 0`, service "ssm", POST "/"; `aws_transport` now forwards to `aws_request` (ENOTSUP stub removed); `ssm_get_parameter`, `ssm_send_command`, `ssm_get_command_invocation` and `ssm_wait_command` all use `ssm_call_api`; status→errno mapping and `aws_wait` bounded polling unchanged.
- tests-cover: every public function against the fake transport, asserting exact X-Amz-Target + Content-Type extra lines, POST /, JSON body, no query, unsigned_payload=0; new `test_build_headers` covers the production header-building seam; response parsing and ENOENT/EACCES/SSM_ERR_AWS_API mapping and waiter behavior remain covered.
- disconfirming: the production `aws_transport` → `aws_request` path is not exercised end-to-end because core/aws exposes no test aws_ctx constructor and no socket is opened; proof stops at the ssm_call extra-header contents plus core/aws's own Amendment 5 tests. No live AWS SSM call was made, so a real service signature rejection would falsify this. No live response fixtures exist.
<!-- RECORD-COMPLETE -->
