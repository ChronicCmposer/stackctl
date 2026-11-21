---
lane: w3-checker
wave: 3
attempt: 2
status: complete
assumptions: state/waves/3.retry-1.md is absent; proceeded on the orchestrator's explicit ATTEMPT:2 operator-authorization brief; D4 applied the exact contracted object ARN in addition to requiring the Fn::Sub form
confidence: high
timestamp: 2026-11-21T06:19:16Z
---
## Evidence
- inbox: empty (w2-tests note already replied in attempt 1; reply file present in inbox/w2-tests/)
- build: `bazel build //...` -> exit 0
- test: `bazel test //deploy/check/... --test_output=errors` -> exit 0 (template_check_test PASSED)
- test: `bazel test //...` -> exit 3 (known wave-4 red: 35 pass / 7 fail; failures are the RELEASE_PREFIXES-removal fallout in cli_ctx, deploy, refresh_ami, binary_verb, guide_examples, contract, stack e2e; none reference deploy/check)
- lint: `bazel build --config=lint-c //deploy/check/...` -> exit 0; `bazel run //tools/lint:lint-yaml` -> exit 0; `bazel run //tools/lint:lint-starlark` -> exit 0 after pinned buildifier `-mode=fix` on deploy/check/BUILD.bazel
- produced:
  - deploy/check/template_check.c
  - deploy/check/template_check_test.c
  - deploy/check/BUILD.bazel
  - deploy/check/testdata/intrinsic_action_ref.yaml
  - deploy/check/testdata/intrinsic_action_if.yaml
  - deploy/check/testdata/intrinsic_resource_ref.yaml
  - deploy/check/testdata/intrinsic_resource_sub.yaml
  - deploy/check/testdata/intrinsic_resource_join.yaml
  - deploy/check/testdata/intrinsic_resource_if.yaml
  - deploy/check/testdata/bare_literal_object_resource.yaml
  - deploy/check/testdata/attached_policy_other_bucket.yaml
  - deploy/check/testdata/operator_policy_overflow.yaml
- disconfirming: state/waves/3.retry-1.md does not exist in the run directory; the seven `bazel test //...` failures are unowned downstream wave-4 work and were not fixed here; the independent retry review has not yet re-run the checker against the new mutation shapes.

## Defects addressed
- D1 (MAJOR): deploy/check/template_check.c:882-1032 adds an Action/Resource resolver (`resolve_node`: Fn::If branch walk, Fn::Sub unwrap, Fn::Join concatenation, Ref/unknown -> unsupported_shape) and rewrites rules 1/2 (`check_operator_s3_scope`, :1390-1470) and rule 4 (`check_reader_statement`, :1478-1540) to consume it. Any unsupported Action/Resource shape now emits the rule diagnostic naming the shape instead of being skipped by the scalar-only walk.
- D2 (LOW): deploy/check/template_check.c:1623-1626 adds `is_operator_attach_policy` (ManagedPolicy + IAM::Policy); :1655-1668 collects AWS::IAM::Policy attached through Users/Roles/Groups under the same scope rules (ManagedPolicyArns branch remains ManagedPolicy-only).
- D3 (LOW): deploy/check/template_check.c:1287-1294 tracks `overflowed` in operator_policies; :1671-1678 emits `operator policy union exceeds the supported maximum of 8 attached policies`; invoked once at :2099.
- D4 (MINOR): deploy/check/template_check.c:1376 defines the exact contracted object ARN; :1448-1452 requires `from_sub` and exact `...-*/*`, so a bare literal that merely matches textually is a violation.

## Pins & injections
none

## Mutation evidence
none
<!-- RECORD-COMPLETE -->
