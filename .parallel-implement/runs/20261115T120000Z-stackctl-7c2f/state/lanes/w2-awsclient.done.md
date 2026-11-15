---
lane: w2-awsclient
wave: 2
status: complete
assumptions: frozen core/ini exposes only ini_upsert_section (no reader) and is outside core/aws globs, so core/aws/ini_read.c is the single credential-reader adapter with documented divergences (case-insensitive keys, #/; comments, ENOENT when access/secret absent) and a cross-test against ini_upsert_section; AWS_MAX_ATTEMPTS=6 means six total attempts (initial try + five retries) and only transient transport errno consume them; callers must zero-initialise aws_resp before aws_request; STACKCTL_ENDPOINT_URL may carry a base path and non-default port; extra signed headers beyond host/x-amz-date/x-amz-security-token are unsupported because sigv4_sign is frozen to that set; curl_global_cleanup is paired one-for-one with curl_global_init per context and relies on libcurl's global reference count for sibling contexts
confidence: high
timestamp: 2026-11-15T03:12:23Z
---
## Evidence
- inbox: empty (orchestrator reply ...mbedtls-config-link.md.reply.md disposition `done`, resolved; new non-blocking escalation w2-awsclient-20261115T031127Z-ini-reader-gap.md filed to orchestrator)
- build: `bazel build //...` -> exit 0 (37 targets)
- test: `bazel test //... --test_output=errors` -> exit 0 (14/14 tests pass)
- test: `bazel test //core/aws:all --test_output=errors` -> exit 0 (aws_test, retry_test, request_test PASSED; request_test now links after the third_party/mbedtls fix)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 55 files, buildifier 19, shellcheck 1, yaml 4, markdown 2)
- red: `bazel test //core/aws:aws_test //core/aws:retry_test` -> exit 3, failing env-strip, size-cap, InvalidSignature-not-skew, and permanent-errno tests (quoted in journal STEP 9)
- green: same targets -> exit 0 after the fixes (journal STEP 10)
- fix-1: `strip_aws_environment()` runs before every early return in `aws_init`; tests cover missing profile and missing HOME (`aws_test.c` env-strip tests)
- fix-2: hand-rolled parser removed from `aws.c`; `core/aws/ini_read.c` adapter added and cross-tested by reading a file written by core/ini (`test_adapter_reads_ini_written_file`)
- fix-3: `clock_skew_code` only RequestTimeTooSkewed/RequestExpired; InvalidSignatureException test asserts not skew
- fix-4: `transport_teardown` calls `curl_global_cleanup` when the paired global init succeeded; `ensure_transport` cleans up when `curl_easy_init` fails
- fix-5: `transport_error_retryable` gates retries to transient errno; test asserts EACCES fails after one attempt and ECONNRESET/ETIMEDOUT retry to the cap
- fix-6: `aws_ini_read_profile` `fstat` size check (>256 KiB -> EFBIG), `ferror`, and grew-past-cap `!feof` guard; test asserts EFBIG
- produced: core/aws/aws.h, core/aws/aws_internal.h, core/aws/aws.c, core/aws/ini_read.c, core/aws/request.c, core/aws/http.c, core/aws/resp.c, core/aws/wait.c, core/aws/BUILD.bazel, core/aws/aws_test.c, core/aws/retry_test.c, core/aws/request_test.c
- disconfirming: real clock-skew detection is exercised only through synthetic responses (no live AWS 403 fixture); `curl_global_cleanup` correctness under multiple concurrent contexts is reasoned from libcurl's documented reference counting but not stress-tested (single-threaded app). Would be falsified by an ASan/valgrind leak report across two contexts or a future core/ini reader whose semantics differ from the adapter. No peer files (core/dns, core/ddns, third_party) were modified by this lane.
<!-- RECORD-COMPLETE -->
