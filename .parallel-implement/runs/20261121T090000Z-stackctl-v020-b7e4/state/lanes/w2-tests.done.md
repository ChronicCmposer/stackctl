---
lane: w2-tests
wave: 2
attempt: 1
status: complete
assumptions: fixtures derived from canonical deploy/stackctl-operator.yaml with the CONTRACT v0.2.0 S3 shape applied (ReleasePrefixes removed, operator/CI bucket-wide, List unconditioned); the three PASS fixtures share the same v0.2.0 base document and each header names the distinct rule it asserts; wildcard_list.yaml intentionally lists both "*" and arn:aws:s3:::* so the contract-pinned substring is emitted
confidence: high
timestamp: 2026-11-21T04:54:44Z
---
## Evidence
- inbox: empty
- produced: deploy/check/testdata/operator_bucketwide_own.yaml
- produced: deploy/check/testdata/list_unconditioned_own.yaml
- produced: deploy/check/testdata/ci_read_bucketwide.yaml
- produced: deploy/check/testdata/wildcard_bucket_objects.yaml
- produced: deploy/check/testdata/wildcard_list.yaml
- produced: deploy/check/testdata/other_project_bucket.yaml
- produced: deploy/check/testdata/users_attached_other_bucket.yaml
- produced: deploy/check/testdata/opaque_getatt_resource.yaml
- produced: deploy/check/testdata/ci_putobject.yaml
- produced: deploy/check/testdata/ci_other_bucket.yaml
- produced: inbox/w3-checker/w2-tests-20261121T045401Z-fixtures-for-checker.md (msgid w2-tests-20261121T045401Z-fixtures-for-checker)
- disconfirming: fixtures are data-only; they are expected to FAIL against the CURRENT v0.1.26 checker (the PASS files especially, since ReleasePrefixes/OPERATOR_CI_PARAMS still exist) until wave 3 lands; no build claim made (no bazel run this wave)
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
