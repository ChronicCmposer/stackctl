---
lane: w4-verbs-stack
wave: 4
status: complete
assumptions: region variant derived by comparing the primary .env REGION with the loaded config REGION (cli_ctx exposes no region_explicit accessor), so an explicit --region equal to the primary region with a same-region sibling remains indistinguishable; core/ini exposes only ini_upsert_section, so provision reads the local aws_access_key_id with a bounded local INI parse and writes via core/ini (escalation filed); core/iam maps InvalidClientTokenId to EACCES, so the fresh-key identity check retries EACCES up to 6 times; deploy prune uses core/s3 ListObjectsV2 single-page results (no continuation-token input) and treats a prune error as a non-fatal warning; previous rollback tag is read from the state release-history file; deploy parameter diff is computed against the current stack's parameters via cfn_stack_parameter (a brand-new stack reports every planned parameter as Added)
confidence: high
timestamp: 2026-11-15T06:07:38Z
---
## Evidence
- inbox: empty (only two pre-existing *.reply.md files; no open inbound items)
- attempt: 3 (retry of the sole remaining minor from review-2: deploy live-preview per-parameter diff)
- build: `bazel build //...` -> exit 0 (70 targets)
- test: `bazel test //...` -> exit 0 (31/31 tests pass); `bazel test //core/cli/deploy:deploy_test --nocache_test_results` -> exit 0
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 123 files, buildifier 33, shellcheck 1, yamllint 8, markdown 2)
- produced: core/cli/provision/{provision.c,provision_internal.h,provision_test.c,BUILD.bazel}; core/cli/deploy/{deploy.c,deploy_internal.h,deploy_test.c,BUILD.bazel}; core/cli/refresh_ami/{refresh_ami.c,refresh_ami_test.c}; inbox/orchestrator/w4-verbs-stack-20261115T053014Z-ini-read-api.md
- fixes (prior attempts, re-review PASS): IAM key lifecycle via core/iam (exactly-one, prune-before-create, rotate-after-identity, 6x invalid-token retry, ini profile write+backup, idempotent); region variant from config not file existence; deploy publish HEAD+GET read-back before stack record; prune keeps 10 newest, protects pinned/previous/just-uploaded, deletes >24h manifest-less garbage; --skip-build on an immutable tag exits 3; live Project-instance count in the preview; direct aws_request/STS removed (iam module); manifest is `<sha>  <member>`; refresh-ami writes example-first and rolls back on failure; repo_root shell-quoted
- fix (attempt 3): deploy live preview now prints a per-parameter diff (`parameter_changes:` header; `Name: Added = new`, `Name: Changed: old -> new`, `Name: Removed = old`), and `--json` carries a structured `parameter_diff` array `[{name,action,old,new}]` with no raw text mixed into JSON. Added `deploy_param_diff_write` (declared in deploy_internal.h) and a shared diff walker; unchanged parameters are omitted.
- RED evidence (attempt 3): `test_param_diff_listing` + `test_json_preview_has_structured_param_diff` fail to build (`undeclared identifier 'deploy_param_diff_write'`) before implementation; the JSON test parses the output with yyjson and asserts the array + Changed/Removed entries.
- RED evidence (prior): disabling the publish read-back fails deploy_test; forcing the identity retry budget to 1 fails provision_test; new refresh-ami test fails if .env is written before .env.example
- disconfirming: production AWS/git/bazel paths are exercised only through injected fakes, so live endpoint behavior is unverified; prune is single-page (buckets with >1000 objects under releases/ may be under-pruned); the parameter diff reflects CFN stack parameters, not per-resource property deltas which the cfn_change struct does not carry
<!-- RECORD-COMPLETE -->
