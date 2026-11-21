---
lane: w1-preflight
wave: 1
attempt: 2
status: complete
assumptions: none
confidence: high
timestamp: 2026-11-21T04:48:09Z
---
## Evidence
- inbox: empty
- produced: .parallel-implement/runs/20261121T090000Z-stackctl-v020-b7e4/state/lanes/w1-preflight.attempt2.done.md
- produced: .parallel-implement/runs/20261121T090000Z-stackctl-v020-b7e4/logs/w1-preflight.md (attempt 1 + attempt 2 entries)
- disconfirming: no build/test claim made (lane is read-only preflight); base commit and anchor lines would be falsified by any new commit or edit to the anchored files.
## Anchors
| id | file | pattern | line(s) |
| --- | --- | --- | --- |
| a1 | deploy/check/template_check.c | must be confined to releases | 1294 |
| a2 | deploy/check/template_check.c | check_operator_s3_scope | 1244 (def); also 1250,1298,1803 |
| a3 | deploy/check/template_check.c | s3:prefix | 1276,1277 |
| a4 | deploy/check/template_check.c | collect_operator_policies | 1353 (def); also 1161,1235,1480,1661,1687,1801 |
| a5 | deploy/check/template_check.c | ReleasePrefixes | 1077,1080 |
| a6 | core/config/config.c | RELEASE_PREFIXES (known_keys) | 75 |
| a7 | core/config/config.c | required_present table entry | 776 |
| a8 | core/config/config.c | comma-list validation | 932 (comment), 935-939 (csv_each + error) |
| a9 | core/cli/provision/provision.c | has_ci | 463 (set); also 414,494,1020,1021,1102 |
| a10 | core/cli/provision/provision.c | EnableCiUser | 1019 |
| a11 | core/cli/provision/provision.c | collect_union | 472 (def); also 996 |
| a12 | core/cli/provision/provision.c | ensure_user_key | 699 (def); also 805,812 |
| a13 | deploy/stackctl-operator.yaml | ArtifactReleases | 235 |
| a14 | deploy/stackctl-operator.yaml | ArtifactBucketList | 226 |
| a15 | deploy/stackctl-operator.yaml | ReleaseRead | 569 |
| a16 | deploy/stackctl-operator.yaml | ReleasePrefixes: | 11 |
| a17 | VERSION | 0.1.26 | 1 |
| a18 | MODULE.bazel | 0.1.26 | 10 |
| a19 | docs/migration.md | Upgrading to v0.1.2 | 246 |
## Pins & injections
none
## Mutation evidence
none
<!-- RECORD-COMPLETE -->
