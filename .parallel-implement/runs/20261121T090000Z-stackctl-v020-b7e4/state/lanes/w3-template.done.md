---
lane: w3-template
wave: 3
attempt: 1
status: complete
assumptions: infra template has no ReleasePrefixes parameter to remove (verified by grep); the 166-line strimserver 08bef3f diff counts 1 vendoring banner line that replaced AWSTemplateFormatVersion, excluded as non-Image-Builder and template-breaking, so 165 Image-Builder content lines were applied verbatim
confidence: high
timestamp: 2026-11-21T05:08:09Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0; `bazel build //deploy/check:template_check` -> exit 0
- produced: `deploy/stackctl-operator.yaml` (v0.2.0 bucket-wide operator + CI-reader grants, ReleasePrefixes param removed, 165 Image-Builder lines upstreamed from strimserver 08bef3f); `deploy/stackctl-infra.yaml` (unchanged — it never carried ReleasePrefixes); `deploy/BUILD.bazel` (unchanged — already exports both templates and lists them as checker data)
- checker: `./bazel-bin/deploy/check/template_check operator deploy/stackctl-operator.yaml` -> exit 0; `./bazel-bin/deploy/check/template_check infra deploy/stackctl-infra.yaml` -> exit 0; fixture liveness operator_bucketwide_own/ci_read_bucketwide/list_unconditioned_own -> 0 and wildcard_bucket_objects/ci_putobject/opaque_getatt_resource -> 1
- test: `bazel test //deploy/check:template_check_test //deploy/...` -> exit 0; `bazel test //core/cli/provision:provision_test` PASSED; `//core/cli/deploy:deploy_test` FAILED only on RELEASE_PREFIXES config-fixture errors (w4-cli-tests scope), not template content
- provenance: `diff deploy/stackctl-operator.yaml <(git -C /var/lib/opencode/dev/strimserver show 08bef3f:deploy/stackctl-operator.yaml)` differs only in the v0.2.0 intentional grant edits plus the vendoring banner line
- disconfirming: did not run full `bazel test //...` (known w4-fixture red); did not validate AWS IAM semantics by deploy — only structural checker + build/test
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
