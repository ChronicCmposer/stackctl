---
lane: w2-deploy
wave: 2
status: complete
assumptions: read IMAGE_BUILDER_PARENT_IMAGE via config_get() rather than a new named accessor (contract C3 field is opaque); deploy_prune_verify uses a tag-only callback plus a prod adapter so the ops seam keeps verify_release's full signature; a zero-byte member counts as size-inconsistent
confidence: high
timestamp: 2026-11-15T20:33:07Z
---
## Evidence
- inbox: empty
- build: bazel --output_base=/tmp/opencode/bazel-w2-deploy build //... -> exit 0
- produced: core/cli/deploy/deploy_internal.h; core/cli/deploy/deploy.c; core/cli/deploy/deploy_test.c
- disconfirming: no live-AWS exercise of the cheap verifier; the S3 manifest GET/member HEAD path is covered only by fake-driven prune-selection tests, so a real S3 error-code mapping bug would not be caught here
<!-- RECORD-COMPLETE -->
