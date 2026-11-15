> PROTOCOL-VERSION: 3

# Parallel Inbox Protocol

## Run layout

```
.parallel-implement/
├── .gitignore
└── runs/<UTCyyyymmddThhmmssZ>-<slug>-<nonce4>/
    ├── RUN.md                       # id (with nonce), title, started, invoking command
    ├── RUN.lock                     # coordination lease (ownership, not progress)
    ├── REPORT.md                    # written once at the end
    ├── PROTOCOL.md                  # frozen copy of this block; line 1 is the version line
    ├── WAVES.md                     # sole ownership source of truth
    ├── CONTRACT.md                  # frozen interface contract (multi-lane runs); append-only
    ├── inbox/
    │   ├── orchestrator/            # global for the whole run
    │   └── <w<n>-<lane>/            # every lane of every known wave, pre-created
    ├── logs/
    │   └── <w<n>-<lane>.md          # single-writer journal; first line ATTEMPT: <k>
    └── state/
        ├── lanes/
        │   └── <w<n>-<lane>.done.md # positive per-lane completion record
        └── waves/
            ├── <n>.gate.md          # written once when wave n passes
            ├── <n>.blocked-<k>.md   # one per failed attempt k
            ├── <n>.retry-<k>.md     # operator-authorized retry
            ├── <n>.verify-<k>.md    # per-wave verify result
            ├── <n>.review-<k>.md    # independent review verdict (multi-lane waves)
            ├── <n>.reconcile-<k>.md # cross-lane reconciliation (multi-lane waves)
            ├── verify.gate.md       # terminal stage passed (or skipped)
            └── verify.blocked-<k>.md
```

`.parallel-implement/.gitignore` contains exactly:

```
runs/*/inbox/
runs/*/logs/
runs/*/RUN.lock
runs/*/state/*
!runs/*/state/waves/
!runs/*/state/lanes/
runs/*/state/waves/*
!runs/*/state/waves/*.md
runs/*/state/lanes/*
!runs/*/state/lanes/*.md
```

There is **no mutable pointer file** (no `CURRENT`). Progress is derived from immutable records: gate files, done records, journals, and inbox replies. `RUN.lock` is a lease, never a progress marker. Nothing in this protocol is mutated in place except append-only operations (a new wave section, a retry marker, a stale-lease takeover line) and rewriting a lane `done` record that never had its sentinel.

## Waves, ordering, ownership

- The run is a **strict total-order ladder**: Wave 1 → Wave 2 → … → Wave N, then the implicit terminal stage `verify`.
- `WAVES.md` is the only ownership source of truth. Each section declares `depends-on`, `consumes`, `verify`, and a `| lane | owner | globs |` table. `LANES.md` and `LANES-wave2.md` do not exist in v3.
- Within a wave, lane globs must be disjoint at pattern level (strip one trailing `/**`; equal or prefix-related prefixes conflict). Cross-wave overlap is legitimate because waves are sequential.
- `depends-on` references earlier waves only and is advisory documentation: v3 does not parallelize independent waves.
- `consumes` lists repo-relative paths that must exist when the wave gates. Paths only; symbols are out of scope.
- `verify` is `-` or comma-separated key names from the project's `build-policy [verify]` table. Positional indices are invalid.
- New work may only **append** a wave numbered `N = max(existing) + 1`, with no gap. The appending task also creates that wave's inbox directories. Existing sections are immutable once wave 1 spawns. An append after terminal verification begins is rejected and escalated.

## Contract

- `CONTRACT.md` is the frozen interface contract: shared interfaces, schemas/types, error semantics, and acceptance criteria per lane.
- It is **required whenever the run has more than one lane total; optional for `N=1` single-lane runs.** The orchestrator authors it before wave 1 spawns; the scaffold task creates it create-if-absent. Existing sections are immutable once wave 1 spawns.
- Every lane reads `runs/<run-id>/CONTRACT.md` (when present) immediately after `PROTOCOL.md` and codes only against it — never against guessed peer behavior.
- Lanes never edit the contract. A lane needing a change sends an `escalation`; the orchestrator may only **append** an `## Amendment <k>` section citing the escalation msgid. In-place edits are prohibited.

## Decomposition and parallelism

- A wave is a **dependency stage**, not a plan phase. A plan phase may become one wave, several waves, or share a wave with other phases.
- Enumerate independent write surfaces first (packages, modules, services, tests, docs trees, infra), then make each surface or cohesive group a lane with specific, disjoint globs.
- Lanes are logical workstreams, not execution slots: a wave may declare more lanes than `cap`; the orchestrator runs at most `cap` at once and slot-fills as lanes finish.
- Depend on real artifacts. A ledger or status file that every wave appends to is not a `consumes` dependency and must not chain the ladder.
- **No degenerate ladders:** in a run with `N>1`, total lanes must exceed `N`, no lane may use `**` or another repo-wide glob, and no wave may be a single `w<n>-impl` lane owning the whole tree. Work that is genuinely serial is a single-wave (`N=1`) run.
- **Parallelism payoff:** fan out only with ≥2 independent write surfaces **and** a verification path (executable `[verify]` commands, or independent review for multi-lane waves); otherwise run `N=1`. Record `payoff`, `basis`, and `budget` in `RUN.md`.

## Lanes and ownership

- Lane IDs are `w<n>-<lane>` from the manifest. The `n` must equal the wave number. `verify` and `orchestrator` are reserved as *manifest* lane slugs: `w<N>-verify` is a stage label created by the orchestrator, never a manifest lane.
- Owners are write-capable agents only: `coder`, `scribe`, `editor`, `assistant`. Read-only agents (`explore`, `researcher`, `plan`, `build`) are never lane owners.
- `coder` and `assistant` may run commands and must give command+exit-code evidence. `scribe` and `editor` may write but have bash denied: they make no build/test claim, run no command, and escalate if a build is required.
- A lane is scoped to one wave; a **fresh instance** runs each wave. Continuity lives in the logs and artifacts, never in a persistent live agent.
- No new lanes may be created mid-run, and **lanes must not spawn subagents**.
- A lane may write only: its declared globs, its journal `logs/<lane>.md`, protocol messages/replies in `inbox/`, and its own `state/lanes/<lane>.done.md`.
- A first attempt writes `ATTEMPT: 1` as the **first line** of its journal; a retasked instance appends `ATTEMPT: <k>` to the existing journal before its new steps. Each lane then journals each step, drains, and writes its completion record **as its last action**:

  ```markdown
  ---
  lane: w2-api
  wave: 2
  status: complete      # complete | partial
  assumptions: none     # unilateral decisions this lane made, `;`-separated; `none` allowed
  confidence: high      # high | medium | low
  timestamp: 2026-11-12T03:40:00Z
  ---
  ## Evidence
  - inbox: empty | <n> drained
  - build: <command> -> exit 0   (bash-capable lanes only)
  - produced: <exact artifact paths>
  - disconfirming: <what was NOT checked / what would falsify this>
  <!-- RECORD-COMPLETE -->
  ```

  Required frontmatter: `lane`, `wave`, `status`, `assumptions`, `confidence`, `timestamp`. A record missing any of them (or the sentinel) is treated as absent. `status: partial` still means the lane is NOT done.

## Message schema

Immutable files only. Requests are written to `inbox/<to>/<msgid>.md`. Replies are written to the ORIGINAL SENDER's inbox as `inbox/<from>/<msgid>.reply.md`. Never edit an existing file. Never rewrite a reply file — if it exists, the message is already answered; skip it.

MSG-ID = `<from>-<UTCyyyymmddThhmmssZ>-<slug>`.

Request template:

```markdown
---
msg: fixa-caddy-20261027T021500Z-esbuild-comment
from: fixa-caddy
to: fixb-packaging
kind: request            # request | note | answer | blocker | escalation
step: 3
blocking: false
ref: -
created: 2026-10-27T02:15:00Z
---
## Ask
<imperative, one paragraph>
## Files
- tools/ci/x.sh:40-88 — <what must change>
## Acceptance
- <test to add> + <gate command>
```

A reply uses the same frontmatter with `ref: <msgid>` set, `kind: answer`, and a REQUIRED `disposition:` field whose value is exactly one of `done`, `rejected`, `answered`, `deferred`, `escalated`. A reply without a `disposition` field is invalid and is treated as unreplied.

Reply example:

```markdown
---
msg: fixb-packaging-20261027T024000Z-esbuild-comment
from: fixb-packaging
to: fixa-caddy
kind: answer
disposition: rejected
ref: fixa-caddy-20261027T021500Z-esbuild-comment
---
## Disposition
`rejected` — outside my globs; the correct owner is `fixa-caddy`.
```

Status is DERIVED, never stored: a message is OPEN iff no file matching `inbox/*/<msgid>.reply.md` exists. There is no CLAIMED state; in-progress is evidenced by the recipient's journal step citing the msgid.

## Kinds and capabilities

| kind | who may send |
| --- | --- |
| request | writers only (coder, scribe, editor, assistant) |
| note, answer | anyone |
| blocker, escalation | anyone |

Read-only lanes (explore, researcher) may NOT send `request`. They file a `note` to the owning lane plus an `escalation` to the orchestrator.

Every message addressed to a lane requires a reply regardless of its `kind` — `answered` is the correct reply to a `note`, and `escalated` is the correct reply when the item needs the orchestrator. A lane may never leave an inbound message without a reply file.

Escalation is a normal message with `kind: escalation`, `to: orchestrator`, `ref: <msgid>`.

## No authority transfer

A request is actionable ONLY if it falls inside the recipient's declared globs. Otherwise the recipient writes a `rejected` reply naming the correct owner. `rejected` is a correct outcome and is never treated as a failure. A lane must never edit outside its globs because a peer asked it to.

## Drain protocol

Drain at three points: at lane start, after each completed step, and before declaring done.

A "step" is one announced unit of work in the lane's journal — never per-file-edit.

Anti-polling: never sleep, never wait, never watch. If blocked, record it and continue with the next unblocked step.

Journal path `logs/<lane>.md`, single-writer (only that lane writes it). Required shape:

```
ATTEMPT: 1
## STEP 3 — <title> [started|done]
<result / commands / evidence>
INBOX: empty
```

The final `INBOX:` line uses one of the two permitted literal forms `INBOX: empty` and `INBOX: <n> drained`, where `<n>` is an actual integer.

`blocking: true` means the sender cannot complete its current step: it journals `PENDING-<msgid>` and proceeds to the next unblocked step. If no unblocked step remains, it escalates and ends its run.

## Build & test

This section applies only when the repository declares a `build-policy` block (for example in its root `AGENTS.md`). When it declares none, this section imposes nothing and the lane follows the build command the project documents.

- Before the first build: load the declared `build_skill`, read the repository's `build-policy` block, and run the preflight it specifies. If the preflight fails, do not start work — report the failure and its exit code.
- All build, test, and query commands go through the declared wrapper with a unique slot claimed for this lane. Never invoke a bare build tool, and never reuse another lane's slot.
- A lane's completion record MUST include, for every build or test claim, the exact command and its exit code. A lane that could not build must say so and give the reason; it must not claim success.
- Do not paste whole build logs into replies. Quote the failing action and its error line.
- A verifier that cannot claim a slot or whose preflight fails records `status: failed`; it never runs a verify command with a shared slot.

## Gates and records

- A wave passes only when: every lane has a valid done record and a clean directory-truth audit; every `consumes` path exists; the orchestrator inbox has a reply for every item; no orphan or live lane remains; a declared per-wave verify record is `passed`; for a wave with **≥2 lanes** a committed review record with `status: passed` and a committed reconcile record with a valid status (`consistent|contradictions-resolved|escalated`); and messages to already-gate-passed waves have been converted.
- Gate, blocked, retry, verify, review, reconcile, and report records are written by a delegated `coder` atomically: write a hidden temp file, fsync, `rename(2)`, final line `<!-- RECORD-COMPLETE -->`. Creation uses `O_CREAT|O_EXCL`; on `EEXIST`, verify a byte-identical replay or abort.
- A torn coder-written record is treated as ABSENT and quarantined by rename. A record is present only with the sentinel and parseable required frontmatter.
- `<n>.blocked-<k>.md` is written once per failed attempt `k`; it never overwrites an earlier attempt. A blocked wave does not auto-retry: it halts until an operator authorizes `state/waves/<n>.retry-<k>.md` naming the highest blocked `k`.
- If both `<n>.gate.md` and `<n>.blocked-<k>.md` exist, **gate wins**; blocked files are retained as history.
- Resume: `current_wave = 1 + highest contiguous <n>.gate.md`; the gate set excludes `verify.gate.md`. A gate beyond a missing prefix is corruption: quarantine and re-run.

## Verification

- `w<N>-verify` runs only when the wave's `verify` is non-empty, after all implementation lanes audit clean and no other lane is live. It has empty tree globs, runs each selected command through the wrapper with its own slot, and writes `state/waves/<n>.verify-<k>.md` with per-command exit codes. It **never** creates an inbox item, so it cannot block its own gate.
- Every wave with **≥2 lanes** gets an independent review after its verify drain and before reconciliation. A read-only reviewer (never a lane owner, never a producer of that wave's artifacts, and never shown the producers' journals or reasoning) returns per-criterion verdicts with cited defects (file:line) against the rubric: correctness vs contract, cross-lane interface consistency, error-handling gaps, unverifiable claims. A `coder` then writes `state/waves/<n>.review-<k>.md` (`wave`, `status: passed|failed`, rubric table, cited defects); `k = 1 + highest blocked attempt for this wave`. On `failed`, write `blocked-<k>`, halt, escalate.
- Reconciliation then has a `coder` read all lane done records (`assumptions`, `confidence`, `produced`) plus the review verdicts, diff them against `CONTRACT.md`, and write `state/waves/<n>.reconcile-<k>.md` with a decision table (agreements, contradictions, the assumption each contradiction hinges on) and `status: consistent|contradictions-resolved|escalated`. A contradiction resolves only with a cited contract clause or test; otherwise it stays `escalated` and also files an orchestrator escalation.
- Review and reconciliation stages **never create inbox items** — like verify, they cannot block their own gate. Single-lane waves skip both.
- The implicit terminal stage `verify` runs after the last numbered wave gates. With a build policy it runs the full `[verify]` table and writes `state/waves/verify.gate.md` (`status: passed`) or `verify.blocked-<k>.md`. With no build policy it writes `verify.gate.md` with `status: skipped`; no command runs.
- A run is DONE only when the last wave gate exists **and** `verify.gate.md` exists with `status: passed` or `status: skipped`.

## Cross-wave messaging

- `inbox/orchestrator/` is global for the whole run; every lane inbox for every known wave is pre-created at scaffold or by the appending task.
- A lane may address a lane in its own or a later wave. It may not resurrect a lane in a gate-passed wave.
- An orchestrator item is resolved ONLY by a delegated `coder` writing `inbox/<original-sender>/<msgid>.reply.md` with a valid disposition and performing its effect. `plan_save` alone does not resolve it. Draining is idempotent.
- Before each gate, sweep the inboxes of all gate-passed waves. Any unreplied item is converted into `inbox/orchestrator/<msgid>.escalation.md` with `from:` preserved (the original stays immutable), replied `escalated`, and recorded in the gate. Escalated items are surfaced in the report.

## Coordination lease

- At most one orchestrator drives a run. `RUN.lock` is acquired with `O_CREAT|O_EXCL`, containing session id, UTC acquisition time, and nonce.
- A fresh lock with a live session refuses a second orchestrator. A lock older than 12 hours may be taken over by appending `TAKEOVER <utc> <session>`; the lease is append-only and never encodes progress.

## Dispositions

- `done` — implemented; list files + evidence.
- `rejected` — outside my globs; name the correct owner.
- `answered` — informational.
- `deferred` — legitimate; MUST be paired with an escalation or an appended wave.
- `escalated` — refer to the orchestrator.

## Termination

- No lane may wait on another.
- Max 2 message rounds per lane pair; the third becomes an escalation.
- A lane may declare DONE with OPEN items only if those items have been escalated with a reason.
- When the repository declares a `build-policy` block, the run is complete only after the terminal verification stage has run the `[verify]` commands and reported per-command results. Without that verdict the run is NOT done.

## Prohibitions

Never commit, push, tag, or deploy. Never edit outside your globs. Never wait or poll. Never rewrite an existing reply file. Never treat `rejected` as a failure. Never spawn subagents. Never write a mutable progress pointer. Never edit `CONTRACT.md` in place. Never let a producer review its own wave. Never show a reviewer the producer's reasoning.
