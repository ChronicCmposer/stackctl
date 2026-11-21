---
lane: w6-checker
wave: 6
attempt: 3
status: complete
assumptions: a long-form `Ref` entry to an existing User/Role/Group logical id is statically resolvable and accepted (D30); a YAML flow collection written as a sequence item (`- [..]`) is a nested list, not a literal name; `!Ref` to a parameter or non-existent logical id is not statically resolvable; policy attachment sections keep their existing unresolved-principal loop in addition to the new entry guard; the non-CI clean fixture adds SomeOtherUser/SomeGroup resources so `!Ref SomeOtherUser` resolves to an existing logical id
confidence: high
timestamp: 2026-11-21T08:41:56Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0 (1/1 target; 217 checks passed)
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 (42/42 tests pass)
- build: `bazel build --config=lint-c //...` -> exit 0
- lint: `bazel run //tools/lint:lint` -> exit 0
- validator: `python3 /var/lib/opencode/.config/opencode/skill/parallel-inbox/validate.py --run <run-dir>` -> exit 0
- produced: deploy/check/template_check.c; deploy/check/template_check_test.c; deploy/check/BUILD.bazel; deploy/check/testdata/ci_usertogroup_users_if_entry.yaml; deploy/check/testdata/ci_usertogroup_users_nested_list.yaml; deploy/check/testdata/ci_usertogroup_users_nonci_ref.yaml; docs/migration.md; logs/w6-checker.md; state/lanes/w6-checker.attempt3.done.md
- disconfirming: No real CloudFormation render or deploy was exercised; the checker is validated only by its own fixtures. The accepted entry forms reflect the resolver as implemented. No source-text pins or injections were added.

## Defects addressed

- D29 (MAJOR) — entry-level silent skip in membership/attachment sections is now fail-closed.
  - `entry_is_statically_resolvable` (`deploy/check/template_check.c:1994-2013`) accepts a literal, a short- or long-form `Ref` to an existing logical id, a known-`!Sub`, or an exactly-resolvable `!Join`; it rejects `Fn::If`/other intrinsic maps, substitution-map `!Sub`, `!Ref` to a parameter/non-existent id, and flow collections kept as scalar tokens (`- [..]`).
  - `section_entries_are_statically_resolvable` (`deploy/check/template_check.c:2015-2035`) walks every entry and emits "entry must be statically resolvable (literal, !Ref of an existing logical id, known-!Sub, or exactly-resolvable !Join); intrinsic or nested forms cannot be checked" without skipping.
  - `AWS::IAM::UserToGroupAddition.Properties.Users`: invoked at `deploy/check/template_check.c:2122-2123` before `section_names_ci_identity`, so an intrinsic/nested entry no longer silently drops the addition, its `GroupName`, and the joined group from the CI set. Fixtures `deploy/check/testdata/ci_usertogroup_users_if_entry.yaml` (`Users: [- !If [EnableCiUserCondition, !Ref CiUser, !Ref 'AWS::NoValue']]`, `GroupName: !Ref WriterGroup`, `WriterGroup` with inline PutObject) and `deploy/check/testdata/ci_usertogroup_users_nested_list.yaml` (`Users: [- [!Ref CiUser]]`) both exit 1 with the entry diagnostic; assertions `deploy/check/template_check_test.c:444-457`.
  - `AWS::IAM::User.Properties.Groups`: invoked at `deploy/check/template_check.c:2150-2151`; the pre-existing `ci_membership_unresolved_ref.yaml` (`Groups: [- !Ref GroupParam]`) still exits 1, and resolvable `!Ref <Group>`/literal-name groups (`ci_groups_membership.yaml`, `ci_groups_literal_name.yaml`) remain clean.
  - Policy `Users`/`Roles`/`Groups`: invoked at `deploy/check/template_check.c:2247-2248` in `check_unresolved_policy_principals`, alongside the existing unresolved-principal loop, so an intrinsic/nested entry that `policy_names_ci_identity` cannot match still fails closed; `ci_reader_attach_if_wrapped.yaml` and `ci_unresolved_principal.yaml` remain exit 1.
  - No false rejection: `deploy/check/testdata/ci_usertogroup_users_nonci_ref.yaml` (clean: `Users: [!Ref SomeOtherUser]` to an existing non-CI user, `GroupName: !Ref SomeGroup` with benign policies) exits 0, assertion `deploy/check/template_check_test.c:458-461`. Canonical `deploy/stackctl-operator.yaml` / `deploy/stackctl-infra.yaml` stay green and all existing fixtures keep their expected outcomes (`bazel test //...` 42/42).

- D30 (LOW) — `docs/migration.md` membership/attachment wording.
  - `docs/migration.md:324-341` now states that sections must be plain lists AND every entry must resolve; lists the accepted entry forms including a long-form `Ref` to an existing identity (`:336`); calls entry-level `Fn::If`/other intrinsic maps, substitution-map `!Sub`, `!Ref` to a non-identity, and nested lists violations; and states the checker fails closed at the entry level and never silently skips such an entry (`:340`). The earlier sentence naming long-form `Ref` as a violating intrinsic-map form was replaced. `CONTRACT.md` was not edited; Amendment 2's "never silently skips" claim now holds.

## Pins & injections
none

## Mutation evidence
none
<!-- RECORD-COMPLETE -->
