---
lane: w4-verbs-instance
wave: 4
status: complete
assumptions: Shared instance-verb substrate lives at core/cli/launch/common (target //core/cli/launch/common:instance_common) consumed by launch/terminate/status/startstop; verbs run against an injectable instance_services vtable; launch resolves the release manifest from S3 and verifies it against the stack release-sha tag and calls instance_manifest_select; STACKCTL_MEMBER and STACKCTL_MEMBER_SHA are additive env vars alongside the frozen STACKCTL_MANIFEST_SHA/STACKCTL_VARIANT; a non-empty variant is derived from the member when --variant is omitted; host-key polling defaults to 60x5s (300s) and --ssh-timeout overrides it; a launch-record append failure tears the new instance down and exits 5 to avoid an unrecorded orphan; status reports bindings as a JSON array in --json mode and as human text lines in default mode; launch removes /run/stackctl-setup.<nonce> on entrypoint success and retains it (with rc) on failure for the reconnect-once reader; no test uses network, live AWS, live DNS or live SSH; no peer globs edited and core/iam only consumed
confidence: high
timestamp: 2026-11-15T06:10:00Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (70 targets)
- test: `bazel test //...` -> exit 0 (31 tests)
- test: `bazel test //core/cli/status:status_test //core/cli/launch:launch_test --test_output=errors` -> exit 0
- test: `bazel test //core/cli/launch/... //core/cli/terminate/... //core/cli/status/... //core/cli/startstop/... --test_output=errors` -> exit 0 (5 test targets)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 123, buildifier 33, shellcheck 1, yaml_check 8, markdown_check 2)
- attempt 3 red: new `test_bindings_json_parses`/`test_bindings_text_reported` against old placement -> `bazel test //core/cli/status:status_test` exit 3 (raw binding text in JSON, output not parseable, text mode missing bindings)
- attempt 3 green: bindings text moved out of json_report into text_report; JSON bindings[] stays -> status_test exit 0
- attempt 3 red: staging-dir cleanup string replaced with `sudo true` -> `bazel test //core/cli/launch:launch_test` exit 3 ("successful setup removes the staging dir"); restored -> exit 0
- red: disabled variant filter in instance_manifest_select -> launch_test FAIL (explicit --variant, selected c member, variant non-empty, pre-spend order, missing member) -> restored GREEN
- red: host-key polling attempts forced to 1 -> launch_test FAIL (console polling, keyscan retry/timeout) -> restored GREEN
- red: sentinel remote_rc_path/reconnect_argv set NULL -> launch_test FAIL (rc path, reconnect argv) -> restored GREEN
- red: re-added pinned config AMI fallback -> launch_test FAIL (no-fallback) -> restored GREEN
- red: blanked record.replaced -> launch_test FAIL (replaced id in launch record) -> restored GREEN
- red: ignored launch-record append failure -> launch_test FAIL (cleanup failure + termination) -> restored GREEN
- red: short-circuited identity guard -> status_test FAIL (exit 3) -> restored GREEN
- red: disabled terminate state guard -> terminate_test FAIL (terminated target rejected) -> restored GREEN
- green: `bazel test //core/cli/launch:launch_test //core/cli/terminate:terminate_test //core/cli/status:status_test //core/cli/startstop:startstop_test //core/cli/launch/common:instance_util_test --nocache_test_results` -> exit 0
- produced: core/cli/launch/launch.c; core/cli/launch/launch_test.c; core/cli/launch/common/instance.h; core/cli/launch/common/instance_runtime.c; core/cli/launch/common/instance_services.c; core/cli/launch/common/BUILD.bazel
- produced: core/cli/terminate/terminate.c; core/cli/terminate/terminate_test.c
- produced: core/cli/status/status.c; core/cli/status/status_test.c; core/cli/status/BUILD.bazel
- disconfirming: AWS/DNS/SSH interactions are fakes (Amendment 4, no network); the on-box S3 pull scripts and rm/rc wrapper are asserted as command text, not executed against a real instance; the manifest sha/member selection is exercised with synthetic manifests; real aws_init/ec2/s3/ssm/iam transports are wired only in production paths not exercised by tests; a live AWS response shape or manifest format differing from the fakes would falsify these assumptions; status S3 garbage detection is single-page (no pagination); the text-mode bindings assertion covers the exact default-format line only
<!-- RECORD-COMPLETE -->
