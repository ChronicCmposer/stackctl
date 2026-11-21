---
lane: w6-checker
wave: 6
attempt: 1
status: complete
assumptions: D24 resolved by documenting the existing global fail-closed policy (and sharpening its diagnostic) rather than adding a CI-relevance filter; only ${ProjectName} is treated as a known pseudo-parameter for scalar !Sub names
confidence: high
timestamp: 2026-11-21T08:16:25Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- build: `bazel build --config=lint-c //...` -> exit 0
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 (42/42)
- lint: `bazel run //tools/lint:lint` -> exit 0 (first run exit 4: buildifier required the new `ci_membership_unresolved_ref.yaml` data entry to be re-sorted in deploy/check/BUILD.bazel; fixed, re-run exit 0)
- produced: deploy/check/template_check.c; deploy/check/template_check_test.c; deploy/check/BUILD.bazel; deploy/check/testdata/ci_identity_sub_unknown_var.yaml; deploy/check/testdata/ci_identity_sub_known_var.yaml; deploy/check/testdata/ci_membership_unresolved_ref.yaml; docs/migration.md; inbox/orchestrator/w6-checker-20261121T081524Z-contract-identity-resolution.md
- disconfirming: No real CloudFormation render or deploy was exercised; the checker is validated only by its own fixtures. D26 fringe parser false-rejections remain by design and were not chased — nested `!Join`, `!Sub` inside a short-form join, a join delimiter containing a comma, and a quoted `!Ref "ProjectName"` still reject legitimate templates (false rejections, not rule-4 bypasses). `${AWS::AccountId}`/`${AWS::Region}` are not accepted in identity names because no existing resolver path supported them; such names fail closed.

## Defects addressed
- D23 (MAJOR): Added `resolve_scalar_sub` (`deploy/check/template_check.c:1653-1690`) and routed all three scalar `Fn::Sub` resolutions through it (`:1803`, `:1807`, `:1864`). It substitutes only `${ProjectName}`; any other `${...}` token (e.g. `${CiSuffix}`) returns unresolved, so `find_ci_identities` counts the name and the fail-closed diagnostic fires. Proof: `testdata/ci_identity_sub_unknown_var.yaml` (CI `UserName: !Sub ${ProjectName}-ci${CiSuffix}` + non-canonical over-broad reader) now exits 1 with "IAM identity CiUser name must be statically resolvable" (was exit 0 before the fix); `testdata/ci_identity_sub_known_var.yaml` (`!Sub ${ProjectName}-suffix-name`) stays clean. Assertions: `template_check_test.c:405-411`.
- D25 (MEDIUM): `add_ci_membership_groups` now takes the checker and emits a fail-closed violation when a CI user's `Groups` entry or a CI `UserToGroupAddition.GroupName` cannot be resolved to a Group resource (`deploy/check/template_check.c:2042-2087`, call at `:2196`) instead of silently skipping. Proof: `testdata/ci_membership_unresolved_ref.yaml` (CI user `Groups: [!Ref GroupParam]`) now exits 1 with "IAM membership entry must be statically resolvable" (was exit 0 before the fix). Assertion: `template_check_test.c:413-416`.
- D24 (MEDIUM): Identity diagnostic reworded to state the policy explicitly — "IAM identity %s name must be statically resolvable (literal or !Sub of known pseudo-parameters); cannot prove it is not the CI identity" (`deploy/check/template_check.c:2202-2206`); membership diagnostics use the same "statically resolvable" wording (`:2060`, `:2080`). Added `### Template checker: identity-name resolution` under `Upgrading to v0.2.0` in `docs/migration.md:300-315`, stating the fail-closed rationale for `TEMPLATE_OVERRIDE` and that parameterized identity names are rejected by design. Filed escalation msgid `w6-checker-20261121T081524Z-contract-identity-resolution` asking for an append-only CONTRACT.md Amendment; CONTRACT.md was not edited.
- D26 (LOW): no code change; recorded above under `disconfirming` as documented limitations.

## Pins & injections
none

## Mutation evidence
none
<!-- RECORD-COMPLETE -->
