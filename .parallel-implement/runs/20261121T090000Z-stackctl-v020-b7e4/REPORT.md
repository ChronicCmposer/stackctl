# Run report — 20261121T090000Z-stackctl-v020-b7e4

- **Run id:** `20261121T090000Z-stackctl-v020-b7e4`
- **Title:** stackctl v0.2.0 — bucket-wide artifact access, ENABLE_CI_USER, checker hardening
- **Base commit:** `25c2dab26b4e9da777b4cfa38d18c949ea6f1009`
- **STATUS: DONE** (waves 1–6 gated; terminal `verify.gate.md` `status: passed`; canary not-required)

env-fidelity: not-required — no lane glob matched
canary: not-required
defects: 33 records (30 unique) — logic 26, observability 5, interface 1, process 1 — open: 9 (>=MAJOR 0) — duplicates: 2 — recurrences: 1 — carried: 9 — waived: 3

## Run summary

Nine lanes ran across six waves (waves 1–4 the declared run structure; waves 5–6 operator-authorized appended fix waves). Waves 1, 2, 5, and 6 are single-lane, so no review/reconcile pair is required for those on lane-count grounds except where a review is declared by the wave ladder; waves 1 and 2 declare no verify. Waves 3 and 5 gated `passed` under a committed, unaltered failing review plus an operator waiver (not as review passes), with D7/D8 and D23 respectively waived and fixed by the appended wave. Wave 6 gated with a passing review. Terminal verification is green on all six commands.

## Waves

| wave | gate status / timestamp | verify record / status | review record / status | carried |
|---|---|---|---|---|
| 1 | passed / 2026-11-21T04:49:32Z | none (no declared verify; `verify: -`) | none (single lane) | - |
| 2 | passed / 2026-11-21T04:55:30Z | none (no declared verify; `verify: -`) | none (single lane) | - |
| 3 | passed / 2026-11-21T06:59:00Z | `3.verify-3.md` passed (attempt 3) | `3.review-3.md` failed (attempt 3; gated under D7/D8 waiver) | D9 |
| 4 | passed / 2026-11-21T07:07:16Z | `4.verify-1.md` passed | `4.review-1.md` passed | D10,D11 |
| 5 | passed / 2026-11-21T08:10:00Z | `5.verify-3.md` passed (attempt 3) | `5.review-3.md` failed (attempt 3; gated under D23 waiver) | D24,D25,D26 |
| 6 | passed / 2026-11-21T08:54:00Z | `6.verify-3.md` passed (attempt 3) | `6.review-3.md` passed (attempt 3) | D31,D32,D33 |

Wave-3 reconcile: `3.reconcile-3.md` `status: escalated` (single committed reconcile record for the attempt that gated). Wave 4 reconcile: `4.reconcile-1.md` `status: consistent`. Waves 5 and 6 are single-lane fix waves, so reconciliation is not required.

## Defects

Derived ledger over 33 defect records (`D1`–`D33`; all IDs present, no gaps). `unique` = records with neither `duplicate_of` nor `supersedes` = 30; `duplicates` = `duplicate_of` records = 2 (D5, D8); `recurrences` = `supersedes` records = 1 (D23); `waived` = `.waiver.md` count = 3; `open` = no `.fix.md` and no `.waiver.md` = 9 (D9, D10, D11, D24, D25, D26, D31, D32, D33); of these, severity ≥ MAJOR = 0.

| id | discovered_by | location | severity | root_class | ef_item | why_missed | link (duplicate_of / supersedes) | status |
|---|---|---|---|---|---|---|---|---|
| D1 | review-3-1 | deploy/check/template_check.c:1286-1324, 1348-1384 | MAJOR | logic | - | the lane's outcome tests only exercised scalar/sequence node shapes; the long-form intrinsic branch of the YAML walker was never covered | - | fixed |
| D2 | review-3-1 | deploy/check/template_check.c:1497-1509 | LOW | logic | - | the frozen fixture set only used ManagedPolicy, so no attached policy via another resource type was exercised | - | fixed |
| D3 | review-3-1 | deploy/check/template_check.c:1458-1470 | LOW | observability | - | the pre-existing OPERATOR_MAX_POLICIES cap was untested at overflow, and the new Users/Roles/Groups collection makes overflow more reachable | - | fixed |
| D4 | review-3-1 | deploy/check/template_check.c:1247-1252, 697-715 | MINOR | logic | - | prefix/suffix text matching was treated as equivalent to the `!Sub` intrinsic-form requirement | - | fixed |
| D5 | review-3-2 | deploy/check/template_check.c:960-973, 1448-1453, 1515-1527, 847-851 | MAJOR | logic | - | the intrinsic resolver tested Fn::If/Ref/Sub-text/Join shapes but not the Fn::Sub two-element sequence (string + substitution map) variant | duplicate_of D1 | fixed |
| D6 | review-3-2 | deploy/check/template_check.c:1412-1414, 1425-1430, 1442-1446 | MEDIUM | logic | - | the bucket-handler exemption predates v0.2.0 and was never re-scoped against the new own-bucket rule | - | fixed |
| D7 | review-3-2 | deploy/check/template_check.c:1536-1542 | LOW | logic | - | contract and fixtures both use the canonical ArtifactReaderPolicy id, so alternate-id coverage was never specified | - | waived |
| D8 | review-3-3 | deploy/check/template_check.c:1570-1581, 1583-1592, 1699-1708 | MAJOR | logic | - | attachment matching was implemented from the policy side against logical ids only; identity-side ManagedPolicyArns and name-based attachment were never modeled | duplicate_of D7 | waived |
| D9 | review-3-3 | deploy/check/template_check.c:1711-1736, 2165-2168, 1763-1769, 1006-1030 | MEDIUM | logic | - | policy collection was defined against resource-level policy documents; inline AWS::IAM::User policies were never enumerated | - | open |
| D10 | review-4-1 | docs/onboarding.md:167 | LOW | logic | - | the onboarding sample was migrated for the required-key change without mapping the old CI-enabled semantic from a non-empty prefix list | - | open |
| D11 | review-4-1 | docs/migration.md:256-260 | MINOR | observability | - | the exact-text claim was checked against the message body only, not the emitted stderr line prefix | - | open |
| D12 | review-5-1 | deploy/check/template_check.c:1656-1658, 1666-1687 | MAJOR | logic | - | rule 4 was modeled around resource-level policy documents and the canonical ArtifactReaderPolicy, never the CI user's inline Policies | - | fixed |
| D13 | review-5-1 | deploy/check/template_check.c:1562-1570, 1579-1583, 1642-1648 | MEDIUM | logic | - | identity discovery was limited to User/Role resource-level name fields; principal-by-reference resolution and group membership were never modeled | - | fixed |
| D14 | review-5-1 | deploy/check/template_check.c:1611, 1614-1617 | MEDIUM | logic | - | substring containment used as an identity predicate, with early return, instead of exact normalized name equality over all candidates | - | fixed |
| D15 | review-5-1 | deploy/check/template_check.c:2174-2181 | MEDIUM | logic | - | inline collection assumed a literal list of literal maps | - | fixed |
| D16 | review-5-1 | deploy/check/template_check.c:1407-1409, 1484-1495, 1011-1018 | LOW | logic | - | statement scanning gates on Action/Resource presence and never considered negated forms | - | fixed |
| D17 | review-5-2 | deploy/check/template_check.c:1731-1732 | MAJOR | logic | - | the parser's closing-bracket consumption after a short-form !Join was never exercised by a fixture | - | fixed |
| D18 | review-5-2 | deploy/check/template_check.c:1931-1972 | MEDIUM | logic | - | CI membership was modeled only through AWS::IAM::UserToGroupAddition, never through the AWS::IAM::User Properties.Groups list | - | fixed |
| D19 | review-5-2 | deploy/check/template_check.c:1945-1949 | MEDIUM | logic | - | only reference-form group names were handled when reading UserToGroupAddition, so a literal GroupName was never mapped to a group resource | - | fixed |
| D20 | review-5-2 | deploy/check/template_check.c:1858-1863 | MEDIUM | logic | - | fail-closed handling was applied to join-derived identity shapes only, so non-Join unresolvable names fell through the discovery loop | - | fixed |
| D21 | review-5-2 | deploy/check/template_check_test.c | LOW | logic | - | fixtures covered only the happy-path resolution and enforcement branches, leaving the parser's closing bracket and the alternative membership and resolution branches untested | - | fixed |
| D22 | review-5-2 | state/lanes/w5-checker.attempt2.done.md:27,47 | LOW | process | - | the done record attributed enforcement to a fixture that short-circuits on the canonical logical id rather than to a fixture that exercises the new identity-resolution path | - | fixed |
| D23 | review-5-3 | deploy/check/template_check.c:1812-1819, 1617-1641, 1861-1870, 2148-2152 | MAJOR | logic | - | only explicitly known substitution shapes were counted as unresolved; an unknown ${Var} inside a scalar Fn::Sub was treated as literal text | supersedes D20 | waived |
| D24 | review-5-3 | deploy/check/template_check.c:1811-1819, 1859-1872, 2148-2152 | MEDIUM | interface | - | fail-closed was applied globally to all identity names without a CI-relevance filter | - | open |
| D25 | review-5-3 | deploy/check/template_check.c:1941-1957, 2029-2031 | MEDIUM | logic | - | group resolution returns "not found" for parameter refs and the membership loop treated that as "no membership" | - | open |
| D26 | review-5-3 | deploy/check/template_check.c:1731-1742, 1617-1641 | LOW | logic | - | the name parser is a hand-written subset parser; these fringe shapes were never in scope | - | open |
| D27 | review-6-1 | deploy/check/template_check.c:2054, 2075-2076, 2091-2100, 2154-2188 | MAJOR | logic | - | membership/attachment iteration reused scalar_count sequence enumeration and never handled or rejected map nodes | - | fixed |
| D28 | review-6-1 | CONTRACT.md (## Amendment 1); docs/migration.md:306-311 | LOW | observability | - | doc text written from the policy intent without reconciling the resolver's accepted forms | - | fixed |
| D29 | review-6-2 | deploy/check/template_check.c:1989-1996, 2074-2076 | MAJOR | logic | - | the plain-sequence guard was applied to the section node only, not to per-entry resolution, so entry-level intrinsic and nested-list shapes fell through the continue | - | fixed |
| D30 | review-6-2 | docs/migration.md:324-330; CONTRACT.md (## Amendment 2) | LOW | observability | - | doc claims were written to the intended policy before entry-level enforcement existed, so they describe behavior the checker does not yet guarantee | - | fixed |
| D31 | review-6-3 | deploy/check/template_check.c:431-433, 2003-2012 | MEDIUM | logic | - | the parser flattens block nested sequences into a single scalar token, so the entry guard sees only the flattened literal | - | open |
| D32 | review-6-3 | deploy/check/template_check.c (parser; block collections only) | LOW | logic | - | the hand-written subset parser covers block collection forms only, the same parser-scope class as D26 | - | open |
| D33 | review-6-3 | docs/migration.md:339 | LOW | observability | - | the doc was written to intent before the block-form flattening behavior was known | - | open |

### Ledger notes

- **D9, D24, D25 — fixed in code, no closing record.** These are wave-5-sourced carried items: D9 (MEDIUM) is carried by `3.gate.md`; D24 and D25 (both MEDIUM) are carried by `5.gate.md`. Their behavior was confirmed fixed in code and in the traced regression by the wave-6 reviewer (`6.review-3.md`), but R4 forbids a closing artifact that postdates the gate of the wave that sourced/carried them (`D23.fix.md` was rejected for exactly this reason). They therefore remain formally carried/open, with no valid `.fix.md`.
- **D23 — waived, later fixed in code.** D23 (MAJOR) is closed by `D23.waiver.md` (operator `operator-20261121T080826Z-waves-3x3`, timestamped before gate 5). The scalar `!Sub` unknown-variable fail-open it records was subsequently fixed in code during wave 6, but the wave-6 `D23.fix.md` was rejected by `validate.py` under R4 (it postdated gate 5), so the waiver remains the closing artifact.
- **D7, D8 — waived and fixed by appended wave 5.** D8 is `duplicate_of: D7`. Both are waived under `operator-20261121T065750Z-retry-cap-5`, and the rule-4 attachment-scope gap was closed by the wave-5 fix records (D12–D22).
- **D5 and D8 are logical duplicates/recurrences** counted as `duplicates` and therefore not part of the 30 unique roots; `D23` is the single `supersedes` recurrence (it re-opens D20's class).
- **D4, D5, D6, D20** each have a `.fix.md` and are counted `fixed`; D5 additionally carries `duplicate_of: D1`, and D20 is superseded by D23.

## Quarantine events

- `state/lanes/w1-preflight.done.md.invalid-20261121T044809Z` — attempt-1 `w1-preflight` done record quarantined after `validate.py` rejected it for missing required sections (`## Pins & injections`, and consequently `## Mutation evidence`). Recorded in `1.blocked-1.md` (validator exit 1). Attempt 2 (`w1-preflight.attempt2.done.md`) superseded it and wave 1 gated `passed` at attempt 2.

## Uncovered env-fidelity classes

None. The run is env-fidelity **not-required** (basis: no lane glob matched), and no defect record carries `root_class: env-fidelity` (verified by scanning all `state/defects/D*.md`).

## Retry history

### Wave 3

- Attempt 1 → `3.blocked-1.md` (D1 MAJOR fail-open). `3.retry-1.md`: operator-authorized retry 1 of max 3, scoped to D1 + D2–D4.
- Attempt 2 → `3.blocked-2.md` (D5 MAJOR recurrence; D6, D7). `3.retry-2.md`: operator-authorized retry 2 of max 3, scoped to D5 + D6 + D7.
- Attempt 3 → `3.blocked-3.md` (D8 MAJOR residual of D7). Retry cap reached. Operator authorization `operator-20261121T065750Z-retry-cap-5` (chat `operator-chat-2026-11-21-retry-cap-5`) waived D7/D8 and appended wave 5 to close the attachment-scope gap before terminal verify. Wave 3 gated `passed` at attempt 3 under the waiver.

### Wave 5

- Attempt 1 → `5.blocked-1.md` (D12–D16). `5.retry-1.md`: authorized by standing `operator-20261121T065750Z-retry-cap-5` (up to 5 retries), retry 1 of 3.
- Attempt 2 → `5.blocked-2.md` (D17–D22). `5.retry-2.md`: retry 2 of 3 (final standard retry), same standing authorization.
- Attempt 3 → `5.blocked-3.md` (D23–D26). Operator authorization `operator-20261121T080826Z-waves-3x3` ("I authorize up to 3 more waves with 3 tries each") waived D23 for the wave-5 gate and appended wave 6. Wave 5 gated `passed` at attempt 3 under the D23 waiver, explicitly not as a review pass.

### Wave 6

- Attempt 1 → `6.blocked-1.md` (D27, D28). `6.retry-1.md`: authorized by `operator-20261121T080826Z-waves-3x3`, retry 1 of 3.
- Attempt 2 → `6.blocked-2.md` (D29, D30). `6.retry-2.md`: retry 2 of 3, same authorization.
- Attempt 3 → `6.review-3.md` passed; residuals F1–F3 carried as D31–D33. Wave 6 gated `passed` at attempt 3 with a passing review.

## Terminal verification

From `state/waves/verify.gate.md` (`stage: verify`, `status: passed`, `timestamp: 2026-11-21T08:56:32Z`):

| command | exit |
|---|---|
| `bazel build //...` | 0 |
| `bazel test //... --test_output=errors --nocache_test_results` | 0 |
| `bazel build --config=lint-c //...` | 0 |
| `bazel run //tools/lint:lint` | 0 |
| `./bazel-bin/deploy/check/template_check operator deploy/stackctl-operator.yaml` | 0 |
| `./bazel-bin/deploy/check/template_check infra deploy/stackctl-infra.yaml` | 0 |

EF evidence: not applicable — run is env-fidelity not-required.

<!-- RECORD-COMPLETE -->
