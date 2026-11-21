---
lane: w5-checker
wave: 5
attempt: 1
status: complete
assumptions: CI identity name is matched by normalizing !Sub / Fn::Sub scalar UserName/RoleName and policy Users/Roles/Groups entries; long-form Fn::Sub sequence forms are not resolved for name matching and stay fail-closed only via logical-id matching
confidence: high
timestamp: 2026-11-21T07:12:16Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (86 targets; "Build completed successfully")
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0 ("Executed 1 out of 1 test: 1 test passes.")
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 ("Executed 42 out of 42 tests: 42 tests pass.")
- lint: `bazel build --config=lint-c //deploy/check/...` -> exit 0; `bazel run //tools/lint:lint-starlark` -> exit 0 (39 files)
- produced:
  - `deploy/check/template_check.c` (rule-4 both-side attachment resolution; operator inline policy scope)
  - `deploy/check/template_check_test.c` (three new outcome assertions)
  - `deploy/check/BUILD.bazel` (three new `data` entries)
  - `deploy/check/testdata/ci_reader_via_identity_arn.yaml`
  - `deploy/check/testdata/ci_reader_by_name.yaml`
  - `deploy/check/testdata/operator_inline_policy_other_bucket.yaml`
- disconfirming: did not exercise a CI identity expressed as a Role with a distinct RoleName, nor a policy attaching via `Roles`/`Groups`; the code handles both by shared attachment-section iteration but no fixture pins them. Did not run the terminal verify stage (orchestrator). Existing 23 fixtures were not modified.

## Defects addressed

### D7/D8 — rule 4 attachment scope (MAJOR)
Rule 4 no longer keys only on the canonical logical id and policy-side logical-id matching.
- `deploy/check/template_check.c:1556-1560` — `ci_identity` carries the CI identity's logical id and its normalized emitted name.
- `deploy/check/template_check.c:1574-1596` — `normalize_emitted_name` resolves `!Sub ${ProjectName}-ci` / long-form `Fn::Sub` scalar / literal to the emitted name.
- `deploy/check/template_check.c:1598-1625` — `find_ci_identity` locates the `<project>-ci` User/Role and captures logical id + name.
- `deploy/check/template_check.c:1627-1635` — `section_names_by_emitted_name` matches `Users`/`Roles`/`Groups` entries by emitted name.
- `deploy/check/template_check.c:1637-1651` — `policy_names_ci_identity` matches the policy-side attachment by logical id (`!Ref`) or by name.
- `deploy/check/template_check.c:1653-1664` — `is_ci_reader_policy` also matches identity-side `ManagedPolicyArns` references.
- `deploy/check/template_check.c:1666-1688` — `check_artifact_reader_policies` collects both sides and applies `check_reader_statement` to every resolved reader policy while keeping the canonical `ArtifactReaderPolicy` path.
Bypass coverage:
- (a) identity-side `CiUser.ManagedPolicyArns: [!Ref EvilReader]` is now resolved via `identity_arns`; fixture `testdata/ci_reader_via_identity_arn.yaml` grants `s3:PutObject` and asserts the rule-4 diagnostic (`template_check_test.c:314-316`).
- (b) policy-side attachment by NAME `Users: [!Sub ${ProjectName}-ci]` is now resolved via `policy_names_ci_identity`; fixture `testdata/ci_reader_by_name.yaml` (non-canonical id `CiReaderByName`) grants `s3:PutObject` and asserts the rule-4 diagnostic (`template_check_test.c:319-321`).
Over-matching is avoided: only `AWS::IAM::ManagedPolicy`/`AWS::IAM::Policy` resources referenced by the CI identity's `ManagedPolicyArns` or naming the CI identity are scanned. Canonical templates and the existing canonical id fixture remain green.

### D9 — operator inline policies (MEDIUM)
- `deploy/check/template_check.c:2165-2184` — `check_operator_inline_policies` finds the operator user (`find_operator_user`) and runs every `Properties.Policies[*].PolicyDocument` through `check_operator_s3_scope` with the `Policies` attachment label, so rule 1 (object ARNs) and rule 2 (ListBucket bucket ARN) apply to inline statements.
- `deploy/check/template_check.c:2269` — the helper is invoked in `check_operator`.
Fixture `testdata/operator_inline_policy_other_bucket.yaml` adds an inline `s3:ListBucket` on `arn:aws:s3:::otherproject-artifacts-...` and asserts the rule-2 diagnostic (`template_check_test.c:324-326`). The canonical operator template's `OperatorUser` has no inline `Policies` key, so it stays green (verified by `expect_file(0, deploy/stackctl-operator.yaml)`).

## Pins & injections
none

## Mutation evidence
none

<!-- RECORD-COMPLETE -->
