---
lane: w5-checker
wave: 5
attempt: 2
status: complete
assumptions: CI identity is matched by exact normalized emitted name equality over all User/Role/Group candidates; !Join ['-', [ProjectName, 'ci']] is resolved exactly and any other unresolvable join-built identity name fails closed; principal entries that cannot be tied to a User/Role/Group resource fail closed
confidence: high
timestamp: 2026-11-21T07:25:01Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0 (86 targets; "Build completed successfully")
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0 (1/1; `template_check_test: 130 checks passed`)
- test: `bazel test //... --test_output=errors --nocache_test_results` -> exit 0 ("Executed 42 out of 42 tests: 42 tests pass.")
- lint: `bazel build --config=lint-c //...` -> exit 0; `bazel run //tools/lint:lint` -> exit 0 (starlark 39, shell 3, yaml 52, markdown 4)
- produced:
  - `deploy/check/template_check.c` (exact CI identity set, inline/group/role rule-4 routing, N4/N5 fail-closed)
  - `deploy/check/template_check_test.c` (seven new outcome assertions)
  - `deploy/check/BUILD.bazel` (seven new `data` entries)
  - `deploy/check/testdata/ci_inline_putobject.yaml`
  - `deploy/check/testdata/ci_inline_other_bucket.yaml`
  - `deploy/check/testdata/ci_reader_group_by_ref.yaml`
  - `deploy/check/testdata/ci_reader_role_by_ref.yaml`
  - `deploy/check/testdata/ci_decoy_identity.yaml`
  - `deploy/check/testdata/operator_policies_if_wrapped.yaml`
  - `deploy/check/testdata/notresource_statement.yaml`
- disconfirming: no fixture drives an unresolvable-principal reference (the fail-closed branch at `template_check.c:2037` is exercised only by inspection); the decoy fixture proves exact-match false-positive/negative behavior but the real identity's positive rule-4 behavior is proven by the pre-existing `ci_putobject.yaml`; terminal verify/review/gate are the orchestrator's.

## Defects addressed

### N1 / D12 (MAJOR) — CI identity inline policies escape rule 4
- `deploy/check/template_check.c:2006-2035` — `check_ci_inline_policies` walks each discovered identity's `Properties.Policies[*].PolicyDocument` through `check_reader_statement`; a non-list `Policies` or a non-literal entry fails closed. Called at `:2098`.
- Fixtures: `testdata/ci_inline_putobject.yaml` (own-object `s3:PutObject`) and `testdata/ci_inline_other_bucket.yaml` (GetObject on another project bucket), asserted at `template_check_test.c:314-322`. Both were RED (exit 0) before the change.

### N2 / D13 (MEDIUM) — Group/Role principals by logical id and membership escape
- `deploy/check/template_check.c:1593-1605` — `ci_identity_name_field` now covers `AWS::IAM::Group` (`GroupName`).
- `deploy/check/template_check.c:1844-1873` — `find_ci_identities` discovers every CI-named User/Role/Group (collection, not one id).
- `deploy/check/template_check.c:1931-1972` — `add_ci_membership_groups` models `AWS::IAM::UserToGroupAddition`: a group the CI user joins becomes a CI-reader identity.
- `deploy/check/template_check.c:1898-1918` — `entry_names_ci_identity` resolves `Users`/`Roles`/`Groups` entries by `!Ref` logical id or exact emitted name; `:1974-1983` applies it to policy attachments.
- `deploy/check/template_check.c:2037-2071` — `check_unresolved_policy_principals` fails closed on a principal entry that cannot be tied to a User/Role/Group resource.
- Fixtures: `testdata/ci_reader_group_by_ref.yaml` (`Groups: [!Ref CiGroup]` + `UserToGroupAddition`, PutObject) and `testdata/ci_reader_role_by_ref.yaml` (`Roles: [!Ref CiReaderRole]`, PutObject), asserted at `template_check_test.c:325-331`.

### N3 / D14 (MEDIUM) — substring + first-match identity selection
- `deploy/check/template_check.c:1866` — identity acceptance is `strcmp(emitted, CI_IDENTITY_NAME) == 0`, i.e. exact normalized equality over ALL candidates with no early return and no substring containment.
- `deploy/check/template_check.c:1737-1827` — `resolve_emitted_name` resolves `!Sub`, long-form `Fn::Sub`, `Fn::Join`, and the scalar `!Join ['-', [ProjectName, 'ci']]` form exactly (`resolve_scalar_join` at `:1644-1734`).
- `deploy/check/template_check.c:1829-1864` — an unresolvable join-built identity name increments `unresolved_join`, and `:2088-2092` turns it into a fail-closed violation rather than guessing.
- Decoy/shadowing prevention: a name that merely contains `-ci` is not an identity. Fixture `testdata/ci_decoy_identity.yaml` places a `CiToolsUser` named `${ProjectName}-ci-tools` with a PutObject policy attached **by name** before the real `${ProjectName}-ci` user (benign reader). Before the fix the substring/first-match path selected the decoy and reported the false positive (RED: "expected clean exit, got 1"); after the fix the fixture is clean (asserted at `template_check_test.c:333-340`), proving the decoy is neither falsely rejected nor able to shadow the real identity. The real identity's positive rule-4 enforcement is proven by `ci_putobject.yaml`.

### N4 / D15 (MEDIUM) — conditional/intrinsic operator inline Policies skipped
- `deploy/check/template_check.c:2578-2605` — `check_operator_inline_policies` rejects a non-list `Policies` and any element without a direct `PolicyDocument` (e.g. `Fn::If`), reporting "operator inline policy entry uses an unsupported intrinsic shape Fn::If".
- Fixture `testdata/operator_policies_if_wrapped.yaml`, asserted at `template_check_test.c:342-347`.

### N5 / D16 (LOW) — NotAction/NotResource bypass
- `deploy/check/template_check.c:1407-1412` — `check_operator_s3_scope` flags `NotAction`/`NotResource` as unsupported negated forms.
- `deploy/check/template_check.c:1506-1511` — `check_reader_statement` does the same for CI/reader statements.
- Fixture `testdata/notresource_statement.yaml`, asserted at `template_check_test.c:349-353`.

## Pins & injections
none

## Mutation evidence
none

<!-- RECORD-COMPLETE -->
