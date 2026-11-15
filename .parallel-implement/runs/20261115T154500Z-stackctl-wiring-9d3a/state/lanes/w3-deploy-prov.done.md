---
lane: w3-deploy-prov
wave: 3
status: complete
assumptions: F15 reuses a new optional deploy_ops.list_releases seam (same lane owns producer and consumer); analysis is bounded to one ListObjectsV2 page so buckets over 1000 release keys may omit older tags; F14 formats/emits the ambiguity diagnostic inside prod_provenance because the frozen ops signature cannot carry tags back; deferred (b) deploy-level test simulates an all-unverifiable prune outcome through the existing prune seam
confidence: high
timestamp: 2026-11-15T20:54:21Z
---
## Evidence
- inbox: empty
- build: bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-w3-deploy-prov build //... -> exit 0
- test: bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-w3-deploy-prov test //... -> exit 0 (42 tests pass)
- lint: bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-w3-deploy-prov run //tools/lint:lint -> exit 0
- targeted: bazel test //core/cli/deploy:deploy_test //core/cli/provision:provision_test -> exit 0
- produced: core/cli/deploy/deploy.c; core/cli/deploy/deploy_internal.h; core/cli/deploy/deploy_test.c; core/cli/provision/provision.c; core/cli/provision/provision_test.c
- disconfirming: F14 has helper-level coverage of tag naming plus the production emission path, not an end-to-end git fixture; F15 full-bucket truncation beyond the first S3 page is documented but untested; the first full `build //...` failed in out-of-scope core/cli/launch/launch.c (concurrent w3-launch work) and only passed on re-run after that peer settled
<!-- RECORD-COMPLETE -->
