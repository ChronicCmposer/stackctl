# REPORT — stackctl wiring fixes v0.1.0 → v0.1.1

Run: `20261115T154500Z-stackctl-wiring-9d3a` · design: `designs/stackctl-wiring-fixes.md` (F1–F22) · protocol v3

## Outcome

**COMPLETE.** All 22 fixes (F1–F22) implemented and independently audited PASS with source evidence. All 4 waves gated; terminal verify passed (build exit 0; tests 42/42 pass, including a fresh `--nocache_test_results` run; lint exit 0). Independent design re-audit verdict: **GO**.

## Wave summary

- **Wave 1** (`w1-launch` F1,F8,F9; `w1-deploy` F2,F3,F4,F22): verify/review/reconcile passed, gated. A review defect (>8 ingress message omitted the count) was fixed in wave 2.
- **Wave 2** (`w2-provision` F5,F6,F11-key,F13 + the >8 count fix; `w2-deploy` F7,F10,F11-pass; `w2-checker` F12): verify/review/reconcile passed, gated. Escalation `w2-provision-20261115T201819Z-config-glob` (a `WAVES.md` glob typo) was resolved via `CONTRACT.md` Amendment 1 (effective surface `core/config/**`).
- **Wave 3** (`w3-launch` F16,F17,F18,F21; `w3-deploy-prov` F14,F15,F20 + deferred F5-warning-trigger fix + all-unverifiable deploy-level test; `w3-refresh` F19): attempt 1 **BLOCKED** by independent review (gate-blocking F14 defect: `prod_provenance` NUL-mutated the tag buffer → empty ambiguity diagnostic). Operator-authorized retry (`3.retry-1.md`) fixed it at the root (local parse buffer, `(+N more)` truncation tail, real-path fake-git regression test, `fake_prune` honors prune flag). verify-2/review-2 passed, gated. `blocked-1` retained as history; gate wins per protocol.
- **Wave 4** (`w4-docs`): `docs/**` + `README.md` updated (key count 36, ingress-slot mapping, "Upgrading to v0.1.1" incl. irreversible CI-user-deletion warning, "Fixed in v0.1.1" summary). Single-lane wave: verify (lint) passed, gated; review/reconcile skipped per protocol.
- **Terminal stage**: `verify.gate.md` status: passed (full `[verify]` table: build/test/lint all exit 0).

## Independent design re-audit

`gradual-beige-grasshopper` (read-only, post-wave-4): **Verdict GO** — F1–F22 all PASS with file:line evidence; none unverifiable.

Residual non-blocking notes (logged for v0.1.2):

1. **F5/F6 union semantics**: `collect_union` ORs `RELEASE_PREFIXES`/`BUCKET_MODULES` across all `.env.*` siblings — clearing prefixes only in the active `.env` won't disable the CI user if a sibling still lists prefixes (docs caveat suggested).
2. **F7 vacuous-verify edge**: a zero-member manifest is treated as verified; requiring ≥1 member line would tighten.
3. **F8 reconnect-timeout edge**: a timeout during reconnect-once maps `ENOTCONN`→exit 7, not `ETIMEDOUT`→exit 4.
4. **F3 ordering informational**: the deploy identity guard runs after read-only STS lookup/cfn init — no mutation precedes it; design-consistent.

## Non-blocking deviations carried (v0.1.2 backlog)

- **Wave 2**: "N kept: unverifiable" summary wording is a superset; the asymmetry fixture covers the declaration-removal branch only.
- **Wave 3**: all-unverifiable deploy-level test is fake-driven (production sweep is unit-covered at `deploy.c:1725-1748`); F19 reads the old value from `.env` only (example-file old value discarded); duplicated semver-scan logic in `prod_provenance` vs the helper; `tags[384]` truncation may clip a fragment; the F14 test leaves a `mkdtemp` dir; `test_keep_on_failure` lacks a hint assertion.

## Escalations

- `w2-provision-20261115T201819Z-config-glob` → `CONTRACT.md` Amendment 1, replied `answered` (resolved).
- Wave 3 review-1 failure → `3.blocked-1.md`; operator authorized retry → `3.retry-1.md` (resolved).

## Operator actions required post-run

- **Tagging v0.1.1 is PROHIBITED BY PROTOCOL and was NOT performed.** Tagging, committing, and pushing are operator actions. The working tree contains all changes uncommitted (29+ modified/new files across `core/`, `deploy/check/`, `docs/`, and `README.md`).
- Review the v0.1.2 backlog above before deciding next steps.

## Run status

**DONE** — last wave gate (`4.gate.md`) and `verify.gate.md` (status: passed) both present.
