---
lane: w2-templates
wave: 2
status: complete
assumptions: CFN cannot split or iterate a CommaDelimitedList without macros, so IngressTcp/IngressUdp remain the canonical port[:cidr] inputs but the template exposes a fixed, documented expansion: 8 indexed Ingress{Tcp,Udp}Port<N>/Cidr<N> parameter pairs, one SecurityGroupIngress per slot conditioned on both port and CIDR being non-empty; stackctl (wave 4 deploy) parses each list item and populates the indexed pair, using the documented default CIDR 0.0.0.0/0 only when the item omits :cidr (configured CIDRs are carried verbatim, no literal world CIDR in any rule); checker enforces this exact 8-slot mechanism for canonical templates and TEMPLATE_OVERRIDE files; ProjectName length is not bounded in the templates because config validation is the single source of truth for the per-region S3 bucket budget; CertBucketEnabled maps from config BUCKET_MODULES containing cert
confidence: high
timestamp: 2026-11-15T03:17:22Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- test: `bazel test //...` -> exit 0 (14 test targets incl. //deploy/check:template_check_test, 9 checks)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 55, buildifier 19, shellcheck 1, yaml_check 8, markdown_check 2)
- produced: deploy/stackctl-operator.yaml; deploy/stackctl-infra.yaml; deploy/check/template_check.c; deploy/check/template_check_test.c; deploy/check/BUILD.bazel; deploy/check/testdata/bad_operator_wildcard.yaml; deploy/check/testdata/bad_operator_action_intrinsic.yaml; deploy/check/testdata/bad_operator_resource_intrinsic.yaml; deploy/check/testdata/bad_infra_export.yaml; deploy/check/testdata/bad_infra_bucket.yaml; deploy/check/testdata/bad_infra_literal_cidr.yaml
- fixed: ingress honors every configured port and CIDR via indexed parameter pairs (no hardcoded 0.0.0.0/0 rule); checker fails closed on Fn::If/Fn::Sub/Ref/Join for Action/Resource; cert policy conditional on CertBucketEnabled; PROJECT length single-sourced to config; ReleasePrefixes required only with CiUser; each negative fixture violates exactly one rule.
- tdd: RED `bazel test //deploy/check:template_check_test` -> exit 1 (missing new fixture inputs); GREEN -> exit 0; per-fixture standalone checker confirms single violation each.
- disconfirming: templates were not deployed to a real AWS account, so CloudFormation resource-property validation beyond the structural checker is not proven; the indexing expansion depends on wave-4 deploy code populating the indexed parameters (not yet written), so an un-updated caller would create no app ingress rules (fail-closed, no exposure); checker's conservative YAML subset rejects YAML styles outside the templates fail-closed
<!-- RECORD-COMPLETE -->
