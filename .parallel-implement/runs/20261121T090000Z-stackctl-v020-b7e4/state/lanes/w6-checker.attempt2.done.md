---
lane: w6-checker
wave: 6
attempt: 2
status: complete
assumptions: intrinsic-map membership/attachment sections fail closed with a section-shape diagnostic rather than an entry-level one; !Ref ProjectName is documented as an accepted identity form alongside known-!Sub and exactly-resolvable !Join; policy section validation lives once in check_unresolved_policy_principals so every policy resource is covered
confidence: high
timestamp: 2026-11-21T08:30:02Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- build: `bazel build --config=lint-c //...` -> exit 0
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0 (1/1 test target; 205 checks passed)
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 (42/42 tests pass)
- lint: `bazel run //tools/lint:lint` -> exit 0
- produced: deploy/check/template_check.c; deploy/check/template_check_test.c; deploy/check/BUILD.bazel; deploy/check/testdata/ci_groups_if_wrapped.yaml; deploy/check/testdata/ci_groups_list_param.yaml; deploy/check/testdata/ci_usertogroup_users_if.yaml; deploy/check/testdata/ci_reader_attach_if_wrapped.yaml; docs/migration.md; inbox/orchestrator/w6-checker-20261121T082904Z-contract-amendment2-membership.md
- disconfirming: No real CloudFormation render or deploy was exercised; the checker is validated only by its own fixtures. The accepted-form documentation reflects the resolver as implemented (literal, !Ref ProjectName, !Sub of ${ProjectName}, exact !Join); other pseudo-parameters such as ${AWS::AccountId} remain rejected. No source-text pins were added.

## Defects addressed
- D27 (MAJOR) — `scalar_count` blind spot in membership/attachment sections, closed uniformly with `section_is_plain_sequence` (`deploy/check/template_check.c:1978-1987`). A section that is NULL or a plain `NODE_SEQ` is accepted; anything else (intrinsic map, long-form `Ref`, `Fn::If`-wrapped list, bare scalar intrinsic) emits "must be a plain list of statically resolvable entries; intrinsic or mapping forms cannot be checked" and is never skipped.
  - (i) `AWS::IAM::User.Properties.Groups`: validated at `deploy/check/template_check.c:2096-2099` inside `add_ci_membership_groups` before iterating; fixture `deploy/check/testdata/ci_groups_if_wrapped.yaml` (`Groups: {Fn::If: [...]}`, joined `WriterGroup` has an inline PutObject) and `deploy/check/testdata/ci_groups_list_param.yaml` (`Groups: !Ref GroupListParam`) both exit 1 with the section diagnostic; assertions `deploy/check/template_check_test.c:418-430`.
  - (ii) `AWS::IAM::UserToGroupAddition.Properties.Users`: validated at `deploy/check/template_check.c:2070-2074` before `section_names_ci_identity`, so the whole addition and its `GroupName` are no longer skipped; fixture `deploy/check/testdata/ci_usertogroup_users_if.yaml` exits 1 with the "UserToGroupAddition Properties.Users" diagnostic; assertion `deploy/check/template_check_test.c:431-436`.
  - (iii) CI-reader policy `Users`/`Roles`/`Groups`: every section is validated in `check_unresolved_policy_principals` at `deploy/check/template_check.c:2188-2200` (labels "IAM policy <section> section"), so `policy_names_ci_identity` (`:2115`) can no longer let an intrinsic-map attachment pass unchecked; fixture `deploy/check/testdata/ci_reader_attach_if_wrapped.yaml` (canonical `ArtifactReaderPolicy` with `Users: {Fn::If: [...]}` naming `CiUser`) exits 1 with the "IAM policy Users section" diagnostic; assertion `deploy/check/template_check_test.c:437-442`.
  - Literal/`!Ref`/known-`!Sub` forms stay green: `ci_groups_membership.yaml`, `ci_groups_literal_name.yaml`, `ci_usertogroup_literal_groupname.yaml`, `ci_membership_unresolved_ref.yaml` (entry-level fail-closed), and canonical `deploy/stackctl-operator.yaml` / `deploy/stackctl-infra.yaml` all retain their expected results; Action/Resource handling was not touched.
- D28 (LOW) — documentation accuracy and contract follow-up.
  - `docs/migration.md:300-332` now states the accepted forms (literal, `!Ref ProjectName`, `!Sub` of the known pseudo-parameter `${ProjectName}`, exactly-resolvable `!Join`), the rejected forms (any other intrinsic, substitution-map `Fn::Sub`, unknown `${...}`), and that membership/attachment sections (`AWS::IAM::User.Properties.Groups`, `AWS::IAM::UserToGroupAddition.Properties.Users`, policy `Users`/`Roles`/`Groups`) must be plain, statically resolvable lists with intrinsic-map forms treated as violations. The prior sentence overstating membership rejection was replaced.
  - Filed escalation `w6-checker-20261121T082904Z-contract-amendment2-membership` (kind escalation, to orchestrator, blocking false) requesting append-only CONTRACT `## Amendment 2` to correct Amendment 1's "any other intrinsic is a violation" overstatement and record the plain-list requirement. `CONTRACT.md` was not edited.

## Pins & injections
none

## Mutation evidence
none
<!-- RECORD-COMPLETE -->
