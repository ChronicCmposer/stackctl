# Contract — stackctl v0.2.0 (run 20261121T090000Z-stackctl-v020-b7e4)

Frozen base: commit 25c2dab26b4e9da777b4cfa38d18c949ea6f1009 (tag v0.1.26), branch main, clean tree. Release identity: v0.2.0 (breaking). All lanes code only against this contract; propose changes via escalation to inbox/orchestrator/, never edit this file.

## Grant model (authoritative)
Every S3 resource ARN uses the trailing `-*` wildcard, no region literal: bucket ARN `arn:aws:s3:::${ProjectName}-artifacts-${AWS::AccountId}-*`, objects end `/*`.

| Principal | List | Get | Put | Delete |
|---|---|---|---|---|
| Operator user `<project>` | unconditioned, own bucket | `<bucket>/*` | `<bucket>/*` | `<bucket>/*` |
| CI user `<project>-ci` | unconditioned, own bucket | `<bucket>/*` | — | — |
| Instance role | unchanged (`releases/*`) | unchanged | unchanged | unchanged |

Certs bucket keeps its existing grants.

## Checker rules (deploy/check/template_check.c)
1. Every S3 object resource in an operator-scope policy must be an `!Sub` literal starting `arn:aws:s3:::${ProjectName}-artifacts-${AWS::AccountId}-` and ending `/*`; opaque (`!Ref`/`!GetAtt`/other intrinsics) and wildcard buckets are violations. This replaces the `/releases/` substring rule.
2. ListBucket no longer needs an `s3:prefix` condition, but its resource must be exactly the project artifact bucket ARN (or the certs bucket for the bucket-handler statement).
3. `collect_operator_policies` also gathers policies attached via `Users`/`Roles`/`Groups` naming the operator user (closes the `Users:[OperatorUser]` gap).
4. `ArtifactReaderPolicy` (CI) is checked: own bucket only, only `s3:GetObject` and `s3:ListBucket`; Put/Delete or other buckets are violations.
5. CI-user template params: `ReleasePrefixes` is removed from OPERATOR_CI_PARAMS; a present-but-undeclared parameter must not be emitted by provision.

## Config (core/config/config.c)
- `RELEASE_PREFIXES` removed from `known_keys`; a present `RELEASE_PREFIXES` is a hard error with EXACT text: `RELEASE_PREFIXES was removed in v0.2.0; set ENABLE_CI_USER=true if it was non-empty, false if it was empty`.
- `ENABLE_CI_USER` is a known, REQUIRED-present boolean (non-boolean rejected).
- Required-present + comma-list handling of the old key is deleted.

## Provision (core/cli/provision/provision.c)
- `has_ci` / `EnableCiUser` driven from the `ENABLE_CI_USER` any-true union of `.env.*` siblings (mirror the `ENABLE_IMAGE_BUILDER` OR-merge); stop reading `RELEASE_PREFIXES`.
- Remove `ReleasePrefixes` template parameter emission.
- `--delete-ci-user`: a true→false CI-user transition refuses before change-set execution unless the flag is given; with the flag it proceeds and warns.
- At `ensure_user_key` (~:699-786) add an in-code comment documenting the key-deletion hazard (PC-4: on a host without the local `[<project>]` profile, all operator IAM keys are deleted and one re-minted); do NOT change key logic.

## Templates (deploy/stackctl-operator.yaml, deploy/stackctl-infra.yaml)
- Operator object grants (Sid `ArtifactReleases` or successor): Get/Put/Delete on `arn:aws:s3:::${ProjectName}-artifacts-${AWS::AccountId}-*/*`.
- Operator List (Sid `ArtifactBucketList`): unconditioned on the project bucket ARN.
- CI `ArtifactReaderPolicy`: `s3:GetObject` on `…-artifacts-…-*/*` + `s3:ListBucket` on the bucket ARN; NO Put/Delete.
- Remove the `ReleasePrefixes` parameter from BOTH templates.
- Upstream strimserver's 166 committed Image-Builder parity lines (from /var/lib/opencode/dev/strimserver at commit 08bef3f, its committed `deploy/stackctl-operator.yaml` state) into the operator template; they add no new S3 object/List resources (their only S3 ARN is the unchanged `…/releases/*`).

## Testdata (deploy/check/testdata/, wave 2, frozen names)
- pass fixtures: `operator_bucketwide_own.yaml`, `list_unconditioned_own.yaml`, `ci_read_bucketwide.yaml`.
- fail fixtures with expected violation substrings: `wildcard_bucket_objects.yaml` (`arn:aws:s3:::*/x/*`), `wildcard_list.yaml` (`arn:aws:s3:::*`), `other_project_bucket.yaml`, `users_attached_other_bucket.yaml` (Users:[OperatorUser] gap), `opaque_getatt_resource.yaml`, `ci_putobject.yaml`, `ci_other_bucket.yaml`.
- w2-tests writes only the YAML files + a note to w3-checker; registration in deploy/check/BUILD.bazel belongs to w3-checker.

## Version and docs
- `VERSION` and `MODULE.bazel` module_version both `0.2.0` (`version_consistency_test` must pass).
- `docs/migration.md` gains an `Upgrading to v0.2.0` section covering: the key rename (exact hard-error text above), the removed `ReleasePrefixes` parameter, the checker rule change, and `--delete-ci-user`. `docs/onboarding.md` and `README.md` updated for `ENABLE_CI_USER`.

## Error semantics
Library functions return 0 or non-zero errno-style codes; only CLI verb layers map to exit codes. stdout reserved for CLI output; diagnostics to stderr. C23. No new config keys beyond `ENABLE_CI_USER`; no new CLI flags beyond `--delete-ci-user`.

## Per-lane acceptance
- w1-preflight: base commit 25c2dab clean tree confirmed; every anchor in the runbook II.2.1 table greps at least once; resolved lines recorded.
- w2-tests: the 10 fixture files exist with the exact names above; note sent to w3-checker.
- w3-checker: `bazel test //deploy/check/...` green including all new fixtures (T-S2/T-S3).
- w3-config: `config_test` green; T-S4/T-S5 behaviors hold.
- w3-provision: `provision` tests (fake AWS) green; T-S6 holds.
- w3-template: `bazel test //deploy/...` green; checker passes canonical templates.
- w4-cli-tests / w4-e2e: every fixture referencing `RELEASE_PREFIXES` or the removed parameter updated; `bazel test //...` green.
- w4-docs: version bumped, migration section added, onboarding/README updated; `bazel test //...` green (T-S1).

## Amendment 1

cites: w6-checker-20261121T081524Z-contract-identity-resolution

The v0.2.0 template checker enforces a fail-closed identity-name resolution policy. Operator/CI identity resources (`AWS::IAM::User`, `AWS::IAM::Role`, `AWS::IAM::Group`) and group-membership entries must have statically resolvable names: a literal, `!Ref ProjectName`, or `!Sub` using only known pseudo-parameters (`${ProjectName}`, and any other pseudo-parameters the resolver demonstrably supports). Any other intrinsic, or any unknown `${...}` variable, in such a name is a violation, because the checker cannot prove the resource is not the CI identity. Consequence: `TEMPLATE_OVERRIDE` files with parameterized identity names are rejected by design; this is documented in `docs/migration.md` under "Template checker: identity-name resolution". This amendment records the policy decision raised as D24 and does not change CONTRACT rules 1–5.

## Amendment 2

cites: w6-checker-20261121T082904Z-contract-amendment2-membership

This amendment corrects Amendment 1's overstatement that "any other intrinsic … is a violation" in an identity name, and records the checker's actual fail-closed policy. An operator/CI identity name is statically resolvable when it is: a literal; `!Ref ProjectName`; a `!Sub` using only known pseudo-parameters (`${ProjectName}`, plus any other pseudo-parameters the resolver demonstrably supports); or an exactly-resolvable `!Join` (for example `!Join ['-', [!Ref ProjectName, 'ci']]`). Any other intrinsic (`!Ref <SomeParam>`, `!GetAtt`, `!ImportValue`, an `Fn::Sub` with a substitution map) or any unknown `${Var}` inside a `!Sub` is a violation.

Additionally, every membership and attachment section — `AWS::IAM::User.Properties.Groups`, `AWS::IAM::UserToGroupAddition.Properties.Users`, and a policy's `Users`/`Roles`/`Groups` — must be a plain sequence of statically resolvable entries. An intrinsic or map form in those sections is a violation; the checker fails closed and never silently skips it.

This amendment records the D27 behaviour and repairs the documentation accuracy issue in D28. It does not change CONTRACT rules 1–5; where its wording differs from Amendment 1, this amendment supersedes Amendment 1.
