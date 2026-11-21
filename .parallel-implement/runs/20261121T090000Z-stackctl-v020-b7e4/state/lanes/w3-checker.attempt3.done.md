---
lane: w3-checker
wave: 3
attempt: 3
status: complete
assumptions: rule 4 scope is the canonical ArtifactReaderPolicy id plus any ManagedPolicy/IAM::Policy attached to the project `<project>-ci` user-or-role (detected from its UserName/RoleName template surface); a one-element scalar Fn::Sub sequence carries no substitution map and stays accepted, while any arity>=2 sequence fails closed
confidence: high
timestamp: 2026-11-21T06:40:12Z
---
## Evidence
- inbox: empty (the w2-tests note's attempt-2 reply was mis-named; wrote the correctly-named `inbox/w2-tests/w2-tests-20261121T045401Z-fixtures-for-checker.reply.md` with `disposition: answered`; no open items)
- build: `bazel build //...` -> exit 0
- build: `bazel build --config=lint-c //deploy/check/...` -> exit 0
- test: `bazel test //deploy/check/... --test_output=errors --nocache_test_results` -> exit 0 (`template_check_test` PASSED, 97 checks; all frozen 10 + attempt-2's 9 + 4 new fixtures green)
- lint: `bazel run //tools/lint:lint-starlark` -> exit 0 (39 files)
- lint: `bazel run //tools/lint:lint-yaml` -> exit 0 (42 files)
- test: `bazel test //... --test_output=summary` -> exit 3, 35 pass / 7 fail — the known wave-4 RELEASE_PREFIXES red state (`cli_ctx`, `deploy`, `refresh_ami`, `binary_verb`, `guide_examples`, `contract`, `stack` e2e); none reference `deploy/check`. Example: `stackctl: config: RELEASE_PREFIXES was removed in v0.2.0`.
- produced (implementation): `deploy/check/template_check.c`, `deploy/check/template_check_test.c`, `deploy/check/BUILD.bazel`
- produced (new fixtures): `deploy/check/testdata/sub_map_resource.yaml`, `deploy/check/testdata/sub_map_action.yaml`, `deploy/check/testdata/bucket_handler_other_bucket.yaml`, `deploy/check/testdata/ci_reader_noncanonical_id.yaml`
- disconfirming: the acceptable-shape boundary for `Fn::Sub` was not probed beyond a one-element scalar sequence; the certs-bucket ListBucket allowance is exercised only by the canonical bucket-handler statement (own+certs), not by a non-handler certs statement; D7 detection requires the CI identity's UserName/RoleName to contain the literal `${ProjectName}-ci` template text (a differently-authored CI name would escape). Interpreter/parser variants outside the repo's YAML subset were not tested.
## Defects addressed
- D5 (MAJOR, duplicate_of D1) — `deploy/check/template_check.c:969-975` (`resolve_node`) now accepts `Fn::Sub` only as the scalar template string / one-element scalar sequence and sets `unsupported_shape = "Fn::Sub"` for any sequence carrying a substitution map, so rules 1/2 and rule 4 fail closed; substitution maps are never resolved. The generic IAM walk mirrors it at `deploy/check/template_check.c:852-859` (`check_resource_node`). Tests: `template_check_test.c:296-300`.
- D6 (MEDIUM, pre-existing) — `deploy/check/template_check.c:1450-1461` removes the blanket bucket-handler rule-2 skip: `ListBucket` is allowed only on `OWN_ARTIFACT_BUCKET_ARN` (or `OWN_CERT_BUCKET_ARN` when the statement co-locates CreateBucket/DeleteBucket), and unresolved shapes under a ListBucket statement now fail closed. New constant `OWN_CERT_BUCKET_ARN` at `:1384`. The canonical handler (own+certs) stays green. Test: `template_check_test.c:303-305`.
- D7 (LOW) — `deploy/check/template_check.c:1557-1610` (`name_is_ci_identity`, `find_ci_identity_name`, `is_ci_reader_policy`, `check_artifact_reader_policies`) replaces the logical-id-only lookup; rule 4 now inspects the canonical `ArtifactReaderPolicy` id plus any `AWS::IAM::ManagedPolicy`/`AWS::IAM::Policy` attached to the project `<project>-ci` identity, without matching unrelated policies. Invocation at `:2170`. Test: `template_check_test.c:309-311`.
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
