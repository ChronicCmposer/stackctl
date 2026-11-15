---
run: 20261115T120000Z-stackctl-7c2f
status: DONE
timestamp: 2026-11-15T07:47:28Z
---
# Run Report — 20261115T120000Z-stackctl-7c2f

## STATUS: DONE

All five wave gates passed — `state/waves/1.gate.md`, `2.gate.md`, `3.gate.md`, `4.gate.md`, `5.gate.md` — and the terminal `state/waves/verify.gate.md` passed. No unresolved escalations remain: the orchestrator inbox had 8/8 items replied with `disposition: done`.

## Payoff

- Mode: **parallel** — 5 waves, 18 lanes, concurrency cap 3.
- Basis: ≥2 disjoint write surfaces (build/vendor, core modules, templates, tests, docs); no build-policy declared at scaffold time, so per-wave verification path was independent review; terminal `[verify]` table run after the ladder.
- Budget: 30.

## Wave summary

| wave | lanes | outcome | retries |
| --- | --- | --- | --- |
| 1 | w1-vendor, w1-config, w1-crypto, w1-local | passed attempt 1; review-1 passed (minors only) | 0 |
| 2 | w2-awsclient, w2-ddns, w2-templates | attempt 1 review FAILED → operator retry → attempt 2 passed (review-2, reconcile-2, gate) | 1 |
| 3 | w3-cfn, w3-ec2, w3-s3, w3-ssm, w3-cliapi | passed; w3-ssm needed attempt 2 after Amendment 5 unlocked X-Amz-Target; review-1/reconcile-1/gate passed | 0 (in-wave retask) |
| 4 | w4-verbs-stack, w4-verbs-instance | attempts 1 and 2 reviews FAILED → operator retries → attempt 3 passed (review-3, reconcile-1, gate) | 2 |
| 5 | w5-main, w5-build, w5-tests, w5-docs | attempts 1 and 2 reviews FAILED → operator retries → attempt 3 passed (review-3, reconcile-1, gate) | 2 |

### Wave 1 — foundations

w1-vendor, w1-config, w1-crypto, w1-local passed at attempt 1. Review-1 passed with minor notes only.

### Wave 2 — network seams and CFN templates

w2-awsclient, w2-ddns, w2-templates: attempt 1 review FAILED with 4 majors — non-authoritative DNS via `ares_getaddrinfo`, NS taken from `h_name`, hardcoded `0.0.0.0/0` ingress + `!Select[0]`, and checker fail-open on intrinsics. Operator-authorized retry (`2.retry-1.md`) produced attempt 2, which passed via review-2, reconcile-2, and the gate.

### Wave 3 — AWS service modules and CLI common API

w3-cfn, w3-ec2, w3-s3, w3-ssm, w3-cliapi passed. w3-ssm required attempt 2 after Amendment 5 unlocked `X-Amz-Target`; review-1, reconcile-1, and the gate passed.

### Wave 4 — CLI verbs

w4-verbs-stack, w4-verbs-instance: attempts 1 and 2 reviews FAILED. Attempt 1 majors: launch S3 manifest resolution, IAM key lifecycle, polling/rc/reconnect, pinned AMI fallback, manifest format, status gaps. Attempt 2 majors: status bindings corrupted `--json`. Operator-authorized retries produced attempt 3, which passed via review-3, reconcile-1, and the gate. New `core/iam` module was created as an orchestrator extension (Amendment 6).

### Wave 5 — wiring, build finalization, tests, docs

w5-main, w5-build, w5-tests, w5-docs: attempts 1 and 2 reviews FAILED. Attempt 1 majors: `--version` runfiles resolution, arm64-only lint pins. Attempt 2 majors: bzlmod canonical repo names missed, network_seam host `rm -rf`. Operator-authorized retries produced attempt 3, which passed via review-3, reconcile-1, and the gate.

## Retries

Retries occurred in wave 2 (×1), wave 4 (×2), and wave 5 (×2) — every one operator-authorized via `state/waves/<n>.retry-<k>.md`.

## Amendments

`CONTRACT.md` is append-only; six amendments were recorded:

1. **C23** — `-std=gnu23` for stackctl-authored C.
2. **TDD** — RED → GREEN → REFACTOR evidence required.
3. **Lint** — all languages, gates every verification.
4. **Hermetic** — bazel-only evidence, pinned tools.
5. **Signed extra headers** — `sigv4_sign_with_headers` + `aws_req.extra_headers` for `X-Amz-Target`.
6. **IAM/STS service module** — new `core/iam`.

## Orchestrator resolutions

Recorded under `state/waves/*.orchestrator-*`:

- **mbedtls-config link fix** — wave-1 latent defect; added `MBEDTLS_FS_IO`, `PK_WRITE_C`, `ASN1_WRITE_C`.
- **amz-target seam** — Amendment 5.
- **iam extension** — Amendment 6 (`4.orchestrator-extension-iam.md`).
- **kh-forget store corruption fix** — wave-1 latent defect found by w5-tests; non-mutating `line_first_field_is` + verbatim copy.
- **message-hygiene fix** — malformed w5-main reply replaced by a canonical valid reply; malformed file kept immutable as history.

## Escalated items surfaced

All 8 orchestrator inbox items were resolved with `disposition: done` replies:

- mbedtls-config-link (w2-awsclient)
- mbedtls-config-link (w2-ddns)
- ini-reader-gap (w2-awsclient)
- ssm-x-amz-target-seam (w3-ssm)
- peer-buildifier (w4-verbs-stack)
- ini-read-api (w4-verbs-stack)
- kh-forget-corrupts-store (w5-tests)
- dispatch-lint-request-unreplied (w5-build)

Accepted deviations recorded in gates: reply-filename naming drift (4 peer answers use answer-msgid filenames, correct `ref:`), and w5-build out-of-glob edits (tools/lint select, BUILD.shellcheck comment) which were orchestrator-sanctioned per the retry records.

## Terminal verify

Full `[verify]` table green: build exit 0, test 40/40 pass (exit 0), lint exit 0.

## Budget

~30 lane-delegations authorized; all used successfully (18 lane implementations + retries + record-writes + resolutions).

## Known residual risks

Non-blocking, from reviews/reconciles:

- `RUNFILES_MANIFEST_FILE`-only layouts are not parsed by `--version`.
- No live AWS/DNS/SSH execution — all hermetic fakes per Amendment 4.
- Deploy prune uses single-page `ListObjectsV2`.
- Status garbage detection is single-page.
- amd64 lint binaries are build-verified but not executed on physical amd64 hardware.
- README:77-78 runfiles candidate list omits `stackctl+*` canonical dirs (ordering is correct).
<!-- RECORD-COMPLETE -->
