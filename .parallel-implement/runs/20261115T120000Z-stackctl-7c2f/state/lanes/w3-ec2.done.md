---
lane: w3-ec2
wave: 3
status: complete
assumptions: ec2_client wraps aws_ctx + fixed region + an injectable transport seam (CONTRACT pins the surface, not signatures; the client makes fake-transport unit tests possible); spot requests set InstanceMarketOptions.SpotOptions.SpotInstanceType=one-time explicitly and omit MaxPrice; ec2_run_instances requires root_device_name (obtained from ec2_describe_images) so the encrypted+DeleteOnTermination root-volume invariants are always encodable; ec2_describe_images treats zero matches as success with count 0 and leaves the hard-error decision to the caller preflight; AWS error responses return EC2_ERR_AWS_API=121 (EREMOTEIO) and are reported to stderr with capacity/UnauthorizedOperation hints; ec2_get_console_output returns success with *output_out=NULL when AWS returns an empty <output/>; waiters return 0 with *timed_out=1 on exhaustion and hold the last observed instance; ClientToken is validated for 1..64 length only (charset left to AWS); instance profile/role wiring is IamInstanceProfile.Name on RunInstances only (no AssociateIamInstanceProfile, matching the spec's launch flow); AMI resolution from SSM/baked/pinned stays with the caller/ssm module - ec2 only validates the resolved id via describe_images
confidence: high
timestamp: 2026-11-15T03:42:12Z
---
## Evidence
- inbox: empty
- build: `bazel build //core/ec2:all` -> exit 0
- test: `bazel test //core/ec2:all --test_output=errors` -> exit 0 (ec2_test PASSED, util_test PASSED)
- red: `bazel test //core/ec2:all --test_output=errors` -> exit 3 before implementation (34+ assertion failures, journal STEP 3)
- green: same command -> exit 0 after implementation (journal STEP 5)
- lint: `bazel run //tools/lint:lint-c` -> exit 0; `bazel run //tools/lint:lint-starlark` -> exit 0
- produced: core/ec2/ec2.h, core/ec2/ec2_internal.h, core/ec2/ec2.c, core/ec2/util.c, core/ec2/instances.c, core/ec2/images.c, core/ec2/console.c, core/ec2/tags.c, core/ec2/BUILD.bazel, core/ec2/ec2_test.c, core/ec2/util_test.c
- coverage: every public function is exercised by ec2_test.c/util_test.c; mutation-checkable behaviors include MinCount=MaxCount=1 order, ClientToken presence, exactly three instance-only tag keys, encrypted/DeleteOnTermination root BDM, spot one-time/terminate/no-MaxPrice, multi-value filter encoding, tag:Project percent-encoding, base64 console decode, nested-<item> XML iteration, error-code mapping, waiter polling counts/timeouts, all EINVAL guards.
- disconfirming: the response bodies are AWS-shaped fixtures, not captured live responses; no live RunInstances/DescribeImages call was made (no network, Amendment 4). Capacity/Unauthorized hints are asserted only by code inspection, not by redirecting stderr. Would be falsified by a live response whose element names differ (e.g. public IP not under <ipAddress>) or by an operator policy that forbids one of the three emitted tag keys.
<!-- RECORD-COMPLETE -->
