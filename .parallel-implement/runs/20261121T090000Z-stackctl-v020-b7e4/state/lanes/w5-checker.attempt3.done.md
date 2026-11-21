---
lane: w5-checker
wave: 5
attempt: 3
status: complete
assumptions: short-form !Join identity names are parsed from the `!Join ['-', [items]]` scalar form and long-form from block `Fn::Join`; an identity with no declared UserName/RoleName/GroupName is auto-generated and cannot equal `<project>-ci`, so only a declared-but-unresolvable name fails closed; CI membership is modelled from both `AWS::IAM::User.Properties.Groups` and `AWS::IAM::UserToGroupAddition`, with group entries resolved by `!Ref` logical id or literal/emitted GroupName
confidence: high
timestamp: 2026-11-21T07:42:00Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (86 targets; "Build completed successfully")
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0 (1/1; `template_check_test: 183 checks passed`)
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 ("Executed 42 out of 42 tests: 42 tests pass.")
- lint: `bazel build --config=lint-c //...` -> exit 0; `bazel run //tools/lint:lint` -> exit 0 (starlark 39, shell 3, yaml 68, markdown 4)
- canonical: `./bazel-bin/deploy/check/template_check operator deploy/stackctl-operator.yaml` -> exit 0; `./bazel-bin/deploy/check/template_check infra deploy/stackctl-infra.yaml` -> exit 0
- produced:
  - `deploy/check/template_check.c` (short-form `!Join` close-bracket fix, fail-closed unresolved names, `Groups`/literal membership resolution)
  - `deploy/check/template_check_test.c` (D17-D21 outcome assertions at `:365-425`)
  - `deploy/check/BUILD.bazel` (sixteen new `data` entries)
  - `deploy/check/testdata/operator_join_identity_name.yaml`
  - `deploy/check/testdata/ci_join_identity_name.yaml`
  - `deploy/check/testdata/ci_join_identity_longform.yaml`
  - `deploy/check/testdata/ci_groups_membership.yaml`
  - `deploy/check/testdata/ci_groups_literal_name.yaml`
  - `deploy/check/testdata/ci_usertogroup_literal_groupname.yaml`
  - `deploy/check/testdata/ci_identity_name_param.yaml`
  - `deploy/check/testdata/ci_identity_name_submap.yaml`
  - `deploy/check/testdata/ci_identity_name_importvalue.yaml`
  - `deploy/check/testdata/ci_identity_name_getatt.yaml`
  - `deploy/check/testdata/ci_inline_second_violation.yaml`
  - `deploy/check/testdata/ci_group_inline_policy.yaml`
  - `deploy/check/testdata/ci_role_inline_policy.yaml`
  - `deploy/check/testdata/ci_notaction.yaml`
  - `deploy/check/testdata/ci_unresolved_principal.yaml`
  - `deploy/check/testdata/ci_decoy_enforced.yaml`
- disconfirming: no fixture exercises a long-form `Fn::Sub` with a substitution map on an identity name (the short-form map is tested); a `Groups`/`GroupName` membership entry that is neither a `!Ref` nor a resolvable literal is skipped rather than failed closed (outside D18/D19's named shapes); terminal verify/review/gate are the orchestrator's, not this lane's.

## Defects addressed

### D17 / F1 (MAJOR) — short-form `!Join` identity names never resolved
- Change: `resolve_scalar_join` (`deploy/check/template_check.c:1733-1742`) now consumes the inner items-list `]`, then requires and consumes the outer argument-list `]`, so a well-formed `!Join [delim, [items]]` resolves to its exact literal; long-form block `Fn::Join` resolves through the same emitted-name path.
- Fixture (a), clean, must PASS: `testdata/operator_join_identity_name.yaml` uses `RoleName: !Join ['-', [!Ref ProjectName, 'instance-role']]`; asserted clean at `template_check_test.c:367`. Before the fix it was falsely rejected ("IAM identity name uses an unresolvable Fn::Join shape"), RED.
- Fixture (b), violation, rule 4: `testdata/ci_join_identity_name.yaml` names the CI user `!Join ['-', [!Ref ProjectName, 'ci']]` and attaches an inline `s3:PutObject` reader; asserted `ArtifactReaderPolicy may grant only s3:GetObject and s3:ListBucket` + `s3:PutObject` at `template_check_test.c:371`. Proves the join resolves to the CI identity and enforcement fires.

### D18 / F2 (MEDIUM) — `AWS::IAM::User.Properties.Groups` membership unmodeled
- Change: `resolve_group_logical_id` (`:1941-1975`) maps a group entry to a Group resource, and `add_ci_membership_groups` (`:1997-2035`, user-side loop `:2020-2035`) adds every group a CI user joins to the CI identity set; `check_ci_inline_policies` then holds that group's policies to rule 4.
- Fixture: `testdata/ci_groups_membership.yaml` gives the CI user `Groups: [!Ref CiSharedGroup]` where `CiSharedGroup` is named `shared-readers` (not `-ci`) and holds an inline `s3:PutObject`; asserted at `template_check_test.c:375`. RED before the change (exit 0).

### D19 / F3 (MEDIUM) — literal group names escape membership resolution
- Change: the same `resolve_group_logical_id` (`:1941-1975`) resolves a literal entry by matching the Group's emitted/literal `GroupName`; it is used for `UserToGroupAddition.GroupName` (`:2011-2016`) and for `Groups` entries (`:2026-2033`).
- Fixtures: `testdata/ci_groups_literal_name.yaml` (`Groups: [shared-readers]`, literal) asserted at `template_check_test.c:378`; `testdata/ci_usertogroup_literal_groupname.yaml` (`UserToGroupAddition.GroupName: shared-readers`) asserted at `:381`. Both RED before the change.

### D20 / F4 (MEDIUM) — unresolvable identity names silently skipped
- Change: `find_ci_identities` (`:1859-1872`) counts any declared-but-unresolvable User/Role/Group name; `check_artifact_reader_policies` (`:2148-2151`) fails closed with `IAM identity <logical id> name cannot be resolved (unsupported intrinsic); cannot prove it is not the CI identity`. `resolve_emitted_name` rejects the scalar `!Sub [template, {map}]` form (`:1811-1819`); `!Ref <param>`, `!ImportValue`, `!GetAtt`, and other intrinsics return 0 through the same path.
- Fixtures: `testdata/ci_identity_name_param.yaml` (`UserName: !Ref CiNameParam`) at `template_check_test.c:385`; `testdata/ci_identity_name_submap.yaml` (`!Sub ['...', {map}]`) at `:388`; `testdata/ci_identity_name_importvalue.yaml` at `:391`; `testdata/ci_identity_name_getatt.yaml` at `:394`. All RED before the change.
- Canonical templates remain green because their identity names are scalar `!Sub ${ProjectName}-...` or `!Ref ProjectName` (verified exit 0 above).

### D21 / F5 (LOW) — coverage gaps and decoy enforcement
- Fixtures/assertions in `template_check_test.c:398-425`:
  - second inline entry after a compliant one: `testdata/ci_inline_second_violation.yaml` (`:401`);
  - inline policy on a CI-named Group: `testdata/ci_group_inline_policy.yaml` (`:403`) and on a CI-named Role: `testdata/ci_role_inline_policy.yaml` (`:405`);
  - `NotAction` (not only `NotResource`): `testdata/ci_notaction.yaml` (`:407`);
  - unresolved principal `!Ref` in all three attachment sections: `testdata/ci_unresolved_principal.yaml` (`:409`, `:413`, `:417`);
  - long-form `Fn::Join` identity name: `testdata/ci_join_identity_longform.yaml` (`:421`);
  - decoy plus real enforcement: `testdata/ci_decoy_enforced.yaml` (`:423`) keeps a benign `${ProjectName}-ci-tools` decoy first and attaches a non-canonical over-broad reader to the real `${ProjectName}-ci` user by name; the rule-4 `s3:PutObject` violation proves the real identity is enforced, while a decoy-selecting (substring/first-match) implementation would exit 0.

### D22 / F6 (LOW) — attempt-2 record overstated enforcement evidence
- Change: this record maps every defect to the fixture and assertion that actually exercises the new path. D17 enforcement is proven by `ci_join_identity_name.yaml` (not `ci_putobject.yaml`); D18/D19 by the group-membership fixtures; D21 decoy enforcement by `ci_decoy_enforced.yaml`. No claim is attributed to a fixture that short-circuits on the canonical logical id.

## Pins & injections
none

## Mutation evidence
none

<!-- RECORD-COMPLETE -->
