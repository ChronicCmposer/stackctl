---
lane: w2-provision
wave: 2
status: complete
assumptions: config module lives at core/config/** because the manifest glob core/cli/config/** names no directory (escalated w2-provision-20261115T201819Z-config-glob)
confidence: high
timestamp: 2026-11-15T20:31:38Z
---
## Evidence
- inbox: empty
- build: bazel --output_base=/tmp/opencode/bazel-w2-provision build //... -> exit 0
- produced: core/config/config.c; core/config/config.h; core/config/config_test.c; core/cli/provision/provision.c; core/cli/provision/provision_test.c
- disconfirming: live-AWS behavior not checked (hermetic fakes only); true->false CiUser detection keys off an existing `CiUserName` stack output, so a real stack missing that output would not warn; no deploy.c pass of ImageBuilderParentImage was verified (owned by w2-deploy); lane did not edit the manifest to fix the core/cli/config glob typo.
<!-- RECORD-COMPLETE -->
