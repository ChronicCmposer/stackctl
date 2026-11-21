> PROTOCOL-VERSION: 5

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
    ├── CONTRACT.md                  # frozen interface contract (multi-lane or qualifying); append-only
    ├── inbox/
    │   ├── orchestrator/            # global for the whole run
    │   └── <w<n>-<lane>/            # every lane of every known wave, pre-created
    ├── logs/
    │   └── <w<n>-<lane>.md          # single-writer journal; first line ATTEMPT: <k>
    └── state/
        ├── lanes/
        │   └── <w<n>-<lane>.done.md # positive per-lane completion record
        ├── defects/                 # created empty by scaffold; no mutable ledger
        │   ├── D<k>.md              # one write-once record per defect
        │   ├── D<k>.fix.md          # write-once; presence = fixed
        │   └── D<k>.waiver.md       # write-once; operator waiver
        ├── canary/                  # canary-qualifying runs with canary: required
        │   ├── grant.md             # agent mode only; operator-issued grant
        │   ├── runbook.md           # operator mode; commands + expected evidence
        │   └── output-<k>.md        # operator mode; verbatim pasted output
        └── waves/
            ├── <n>.gate.md          # written once when wave n passes
            ├── <n>.blocked-<k>.md   # one per failed attempt k
            ├── <n>.retry-<k>.md     # operator-authorized retry
            ├── <n>.verify-<k>.md    # per-wave verify result
            ├── <n>.review-<k>.md    # independent review verdict (multi-lane or EF-only)
            ├── <n>.reconcile-<k>.md # cross-lane reconciliation (multi-lane waves)
            ├── verify.gate.md       # terminal stage passed (or skipped)
            ├── verify-<k>.gate.md   # terminal re-verify before canary attempt k≥2
            ├── verify.blocked-<k>.md
            ├── canary-<k>.gate.md   # canary attempt k passed
            └── canary.blocked-<k>.md # canary attempt k failed / awaiting operator
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
!runs/*/state/defects/
runs/*/state/defects/*
!runs/*/state/defects/*.md
!runs/*/state/canary/
runs/*/state/canary/*
!runs/*/state/canary/*.md
```

There is **no mutable pointer file** (no `CURRENT`). Progress is derived from immutable records: gate files, done records, journals, and inbox replies. `RUN.lock` is a lease, never a progress marker. Nothing in this protocol is mutated in place except append-only operations (a new wave section, a retry marker, a stale-lease takeover line) and rewriting a lane `done` record that never had its sentinel.

## Waves, ordering, ownership

- The run is a **strict total-order ladder**: Wave 1 → Wave 2 → … → Wave N, then the implicit terminal stage `verify`.
- `WAVES.md` is the only ownership source of truth. Each section declares `depends-on`, `consumes`, `verify`, and a `| lane | owner | globs |` table. `LANES.md` and `LANES-wave2.md` do not exist in this protocol.
- Within a wave, lane globs must be disjoint at pattern level (strip one trailing `/**`; equal or prefix-related prefixes conflict). Cross-wave overlap is legitimate because waves are sequential.
- `depends-on` references earlier waves only and is advisory documentation: this protocol does not parallelize independent waves.
- `consumes` lists repo-relative paths that must exist when the wave gates. Paths only; symbols are out of scope.
- `verify` is `-` or comma-separated key names from the project's `build-policy [verify]` table. Positional indices are invalid.
- New work may only **append** a wave numbered `N = max(existing) + 1`, with no gap. The appending task also creates that wave's inbox directories and re-runs env-fidelity qualification on the new globs; a run can become qualifying mid-run and then requires an EF amendment before the wave spawns. The only exception to "no append after terminal verification begins" is a canary fix wave (`N+1`), which runs the full ladder before a re-verify. Existing sections are immutable once wave 1 spawns.

## Contract

- `CONTRACT.md` is the frozen interface contract: shared interfaces, schemas/types, error semantics, and acceptance criteria per lane.
- It is **required whenever the run has more than one lane total, and mandatory for every env-fidelity-qualifying run at any N; optional only for non-qualifying `N=1` runs.** The orchestrator authors it before wave 1 spawns; the scaffold task creates it create-if-absent. Existing sections are immutable once wave 1 spawns.
- Every lane reads `runs/<run-id>/CONTRACT.md` immediately after `PROTOCOL.md` and codes only against it — never against guessed peer behavior.
- Lanes never edit the contract. A lane needing a change sends an `escalation`; the orchestrator may only **append** an `## Amendment <k>` section citing the escalation msgid. In-place edits are prohibited.

## Environment Fidelity

- Qualification is **mechanical and upgrade-only**. A run is qualifying iff any lane glob in any wave matches a default pattern: `**/deploy*.sh`, `**/setup*.sh`, `**/install*.sh`, `**/lib/**/*.sh`, `**/*.service`, `**/*.timer`, `**/*.socket`, `**/systemd/**`, `**/*.conf.d/**`, `**/imagebuilder/**`, `**/image-builder/**`, `**/*component*.y*ml`, `**/cloudformation/**`, `**/*.cfn.y*ml`, `**/*.template.y*ml`, `**/packer/**`, `**/udev/**`, `**/sudoers*`, `**/cron*/**`.
- A project may add patterns in one fenced `env-fidelity-paths` block in its `AGENTS.md`; the block is additive and can never remove a default.
- `RUN.md` records `env_fidelity: required|not-required` and `env_fidelity_basis: <glob → pattern|no lane glob matched|upgraded — <reason>>`. The orchestrator MAY upgrade `not-required` to `required`; it MUST NOT downgrade. Validation recomputes qualification. Appended waves re-run qualification and can only make a run qualifying.
- A qualifying run MUST have an `## Environment Fidelity` section in `CONTRACT.md`, authored before wave 1 spawns. Silent omission fails validation. `EF1`–`EF8` are the frozen floor; projects add `EF9+` with the same grammar.
  - `EF1` Privilege & umask: every file crossing a privilege boundary pins mode/ownership at creation; tests reproduce a restrictive umask.
  - `EF2` PATH under sudo / non-interactive shells: sudo's secure_path resolves commands; remote/sudoed invocations state which PATH resolves them.
  - `EF3` Self-matching patterns: every `pgrep -f`/`grep -f` pattern is tested against its own argv and a real matching process.
  - `EF4` Boot-time services: first-boot enabled units are enumerated, each accepted with a reason or masked; a bake audit enforces the set difference.
  - `EF5` Bounded waits: every ssh, subprocess, and remote command names its timeout; no unbounded probe exists.
  - `EF6` Error-path observability: every refusal carries the failing probe's return code and captured output.
  - `EF7` Real-rendering variance: accepted external-tool output matches what real binaries emit, pinned by executing them where available.
  - `EF8` Provisioning prerequisites: IAM permissions, log groups, quotas, and service-linked roles are enumerated and verified by canary or deploy dry-run.
- Row grammar (exactly one row per EF id): `EF<n>: <surfaces> — <property> — <decision> — proof: in-lane|canary|both`, or `EF<n>: not applicable — <reason>`. The `proof:` tag makes `in-lane`/`both` items lane test obligations and `canary`/`both` items canary assertions. A skipped in-lane test is not a pass and forces the item to canary.
- Image-touching runs: `EF4` MUST contain a boot-service allowlist (`accept <unit> — <reason>` or `mask <unit> — <lane>`). The image-build lane runs an audit after installation and before finalization that computes `enabled − accepted` and `declared-masked − actually-masked`, prints both sets, and exits `1` if either is non-empty.
- **Closure rule:** an env-fidelity defect whose `ef_item:` is `none` obliges the next design touching that project to add an EF9+ item; the report lists it under `## Uncovered env-fidelity classes`.

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
  attempt: 1            # REQUIRED for every attempt in v5, including the first
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
  ## EF evidence                       (qualifying runs only; one row per applicable in-lane/both item)
  | item | test id | exact command | exit code | pass|skipped |
  | EF1 | tests/deploy_lock_test.sh::umask077 | bash tests/deploy_lock_test.sh umask077 | 0 | pass |
  ## Pins & injections               (every diff-scoped pin and injection this lane owns, or the literal word `none`)
  | id | kind | test file:line | mechanism | invariant guarded |
  | P1 | pin | tests/deploy_lock_test.sh:42 | awk source pin on the umask preamble | lock mode pinned at creation |
  ## Mutation evidence               (one row per mutation kill; terminal verify IGNORES this section)
  | pin id | mechanism | mutation (exact) | rerun (exact) | exit | failing assertion |
  | P1 | sed | sed -i 's/^chmod 600/:/' <scratch>/deploy.sh | bash <scratch>/deploy_lock_test.sh | 1 | expected mode 0644, got 0600 |
  <!-- RECORD-COMPLETE -->
  ```

  Required frontmatter: `lane`, `wave`, `attempt`, `status`, `assumptions`, `confidence`, `timestamp`. A record missing any of them (or the sentinel) is treated as absent. `status: partial` still means the lane is NOT done.

  Done-record naming tracks the attempt: attempt 1 is `<lane>.done.md`, attempt `k ≥ 2` is `<lane>.attempt<k>.done.md` (the `.attempt<k>.done.md` form); the `attempt:` value MUST agree with the filename, and "latest" means the highest attempt present.

  `## Pins & injections` declares every diff-scoped structural pin and failure-injection shim the lane introduced or modified in this run (see "Test evidence"); when there are none, the body is the literal word `none`. `## Mutation evidence` records one row per mutation kill; the `pin id` cell may list several ids (a single kill can prove several pins), and the union of killed ids must cover the declared pins. Mutation rows live only here — never in `## EF evidence` — because their `exit` is intentionally non-zero.

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

## Test evidence

- **Outcome assertions are primary:** exit codes, file bytes and modes, output lines, state transitions. "The code called X" is not an outcome.
- **Structural pins are secondary and mutation-proven:** a source-text pin is legitimate only for invariants unobservable at runtime, and each pin or injection introduced or modified by the lane in this run (**diff-scoped**) MUST be paired with (a) a runtime outcome test and (b) a **mutation kill** — a recorded edit to the implementation that the paired test must fail on. The kill runs on a scratch copy (never the repo tree) and is recorded in the lane's `## Mutation evidence` section. An unverifiable pin, a pin absent from `## Pins & injections`, or a declared pin/injection without a killing mutation row is a defect of severity ≥ `MAJOR`.
- **Diff-scoped pins and injections:** mandatory mutation evidence applies to every structural pin (awk/grep source pin) the lane added or changed, and every **injection** — a test-controlled substitution of a real command (sudo/systemctl/chmod/chown/ssh/sed) whose failure path is the asserted behavior. Pre-existing untouched pins are out of scope (but still citable if wrong); pure environment-modeling shims that assert a runtime outcome (umask→mode, secure_path→resolved-binary) owe nothing.
- **Mutation rows are separate from EF evidence:** the terminal verify step explicitly **ignores `## Mutation evidence`** — it re-executes only `## EF evidence` commands — because a mutation row's expected exit is non-zero. A mutation the suite survives (exit 0) is itself a defect of severity ≥ `MAJOR`.
- **Shims model the environment, never the answer:** a fake `sudo`/`systemctl`/ssh may reproduce privilege drop, secure_path, non-zero rc, latency, or umask, but must not encode the expected result. A test that can only pass is vacuous — a defect of severity ≥ `MAJOR` with `root_class: env-fidelity`.
- **Real binaries for environment properties:** use real `timeout`+`pgrep`, a real restrictive umask, and `runuser`/`setpriv` for non-root. A skipped EF test is reported as `skipped`, never `pass`; an item whose only evidence is skipped is forced to `proof: canary`.
- A lane done record gains an `## EF evidence` table with one row per applicable `in-lane`/`both` item: `| EF1 | tests/deploy_lock_test.sh::umask077 | bash tests/deploy_lock_test.sh umask077 | 0 | pass |` (`item | test id | exact command | exit code | pass|skipped`).
- Evidence is reproduced, not trusted: the per-wave verify re-executes every cited command. A missing test, a different exit code, or a non-existent command fails verify and then writes a `D<k>` citing the verify record.

## Defect records

- `state/defects/` is created empty by the scaffold. Each defect is one write-once record using the standard primitive (hidden tmp → fsync → `rename(2)`, `O_CREAT|O_EXCL`, `<!-- RECORD-COMPLETE -->`). There is no mutable ledger; gate audits and the report derive a ledger table.
- ID allocation: `k = 1 + highest existing D<k>.md` (sentinel or not). Create with exclusive create; on `EEXIST` re-scan and retry with max+1. A byte-identical replay is already written. Gaps from quarantined torn records are permitted and reported.
- Severity is totally ordered: **CRITICAL > HIGH > MAJOR > MEDIUM > MINOR > LOW**. The single blocking threshold is **≥ MAJOR**, applied identically at wave gates (R1), the terminal audit, and the REPORT headline's `open (>=MAJOR m)` count. Severity is assigned by the rubric in "Verification", not by free judgment.
- `D<k>.md` frontmatter is required: `id`, `discovered_by` (`review-<n>-<k>|verify-<n>|test|canary-<k>|operator|post-release|w<n>-<lane>`), `location`, `severity` (`CRITICAL|HIGH|MAJOR|MEDIUM|MINOR|LOW`), `severity_basis` (one clause naming the rubric row or the concrete consequence that sets the severity), `root_class` (`env-fidelity|logic|interface|observability|process`), `ef_item` (`EF<n>|none`, required when `root_class: env-fidelity`, else `-`), `why_missed`, `source`, `timestamp`. `why_missed` is mandatory, one sentence, and names a mechanism — never a person or model; `-` is invalid. `source` points at the **already-written stage record** that cited the defect — a wave record (`state/waves/<n>.*`), a canary or verify record (`state/waves/canary*.md` / `state/waves/verify*.md`), or a lane record (`state/lanes/<lane>.*`). Write that stage record first, then the `D<k>` citing it (for review, verify, and canary sources); a `D<k>.source` must reference an already-committed record.
- Optional linkage records a re-find of an existing issue: `duplicate_of: D<j>` when the prior defect was **open** at discovery time (no pre-discovery `.fix.md`), or `supersedes: D<j>` when the prior defect was **closed** (a `.fix.md` existed before this record) — i.e. a fix that did not hold. A linked record still carries the full required frontmatter (including `severity_basis`); linkage never replaces the `why_missed` mechanism sentence. Links must be **acyclic** and reference an **existing lower-numbered** record; a dangling or forward link is invalid.
- `D<k>.fix.md` (`id`, `fixed_by`, `verified_by`, `timestamp`) and `D<k>.waiver.md` (`id`, `reason`, `operator_msgid`, `timestamp`) are write-once. A defect with neither is open; presence is the state and nothing is rewritten.
- **R4 — fix/waiver records are gate-time artifacts:** a `.fix.md` or `.waiver.md` is written **when the defect is closed, by the stage that closes it**, and MUST carry a `timestamp` **earlier than the gate** it supports. A fix/waiver written or timestamped at or after its wave gate is invalid, and a gate that relied on it is invalid (quarantined). Never batch-write fix or waiver records after the run.
- `D<k>.fix.md` is written by the **retry review** that re-verifies the fix (a producer may not certify its own fix); `verified_by:` names that review. In a wave with no review (a non-qualifying single-lane wave), the **gate writer** dispositions the defect and writes `D<k>.fix.md` with `dispositioned_by: gate-<n>`.
- Writers: the coder writing a review writes every defect that review cites; verify writes EF-evidence mismatches (`verify-<n>`); the coder writing a canary record writes the canary record first and then its findings citing it; a lane's later attempt writes its own finding before re-task. For review, verify, and canary findings the stage record that evidences the defect is written first, then the `D<k>` citing it. A post-release defect is a `post-release` record in the run's `state/defects/`; the run directory remains the durable home and the ledger is regenerated on demand.

## Gates and records

- A wave passes only when: every lane has a valid done record and a clean directory-truth audit; every `consumes` path exists; the orchestrator inbox has a reply for every item; no orphan or live lane remains; a declared per-wave verify record is `passed`; for a wave with **≥2 lanes** a committed review record with `status: passed` and a committed reconcile record with a valid status (`consistent|contradictions-resolved|escalated`); messages to already-gate-passed waves have been converted; and **(12) open-defect block** — no defect record whose `source` cites this wave has severity ≥ MAJOR without a `.fix.md` or `.waiver.md` that predates this gate (R4). MEDIUM/LOW defects on an otherwise-passing wave do not block: record them in the gate record as `carried: D3,D5` (grammar `carried: D<k>,D<k>,…`, or `-` when none) and surface them as open items in the REPORT; they are not force-reassigned to a later lane.
- A gate or review record that `validate.py --run` rejects is **quarantined**: renamed `<name>.invalid-<utc>` (reusing the torn-record convention). The wave re-enters the rejected stage at the same attempt number `k`; quarantined names never match the gate/review record patterns and are ignored by resume contiguity. Quarantine events are listed in the REPORT.
- A gate, verify, or canary record is written only after the coder runs `validate.py --run <run-dir>` and gets exit 0; a non-zero exit routes the wave to `blocked`/quarantine instead of writing the record. Write the stage record (verify/canary) first, then any `D<k>` it evidences, so every `source` names an already-committed record.
- Gate, blocked, retry, verify, review, reconcile, and report records are written by a delegated `coder` atomically: write a hidden temp file, fsync, `rename(2)`, final line `<!-- RECORD-COMPLETE -->`. Creation uses `O_CREAT|O_EXCL`; on `EEXIST`, verify a byte-identical replay or abort.
- A torn coder-written record is treated as ABSENT and quarantined by rename. A record is present only with the sentinel and parseable required frontmatter.
- `<n>.blocked-<k>.md` is written once per failed attempt `k`; it never overwrites an earlier attempt. A blocked wave does not auto-retry: it halts until an operator authorizes `state/waves/<n>.retry-<k>.md` naming the highest blocked `k`. The wave-retry cap is hard: a wave may be retried at most 3 times, so only `retry-1` and `retry-2` are authorizable. A `<n>.retry-3.md` is invalid (the validator rejects it); after `<n>.blocked-3.md` the orchestrator must offer the operator **waive, re-scope, or abandon**.
- If both `<n>.gate.md` and `<n>.blocked-<k>.md` exist, **gate wins**; blocked files are retained as history.
- Resume: `current_wave = 1 + highest contiguous <n>.gate.md`; the gate set excludes `verify.gate.md` and `verify-<k>.gate.md`. A gate beyond a missing prefix is corruption: quarantine and re-run.
- Audit additions beyond the v3 checks: (9) **defect completeness** — every defect cited in a wave's review records has a `D<k>.md` whose `source` names that review, and every `D<k>` sourced to the wave cites an existing record; (10) **EF coverage and mutation proof** — in a qualifying wave every lane done record has an `## EF evidence` row for every applicable `in-lane`/`both` item, and independently every lane done record's `## Mutation evidence` killed-id union must cover every diff-scoped pin/injection it declares; (11) **review validity** — every review record in a qualifying run carries the criterion-5 row, and every qualifying single-lane wave has its EF-only review; (12) **open-defect block** — every defect sourced to this wave is fixed/waived when ≥ MAJOR, or fixed/waived/carried when MEDIUM/LOW. Checks 9–12 are executed mechanically by `validate.py --run`, not left to prose.
- Terminal audit: the canary verdict exists and is consistent with `RUN.md` `canary:`/`canary_executor:`; a passed canary references the latest `verify.gate.md` or `verify-<k>.gate.md`; and no defect of severity **≥ MAJOR** is open (each such `D<k>` has a `.fix.md` or `.waiver.md`), otherwise the run is NOT DONE.

## Verification

- `w<N>-verify` runs only when the wave's `verify` is non-empty, after all implementation lanes audit clean and no other lane is live. It has empty tree globs, runs each selected command through the wrapper with its own slot, and writes `state/waves/<n>.verify-<k>.md` with per-command exit codes. It **never** creates an inbox item, so it cannot block its own gate.
- Every wave with **≥2 lanes** gets an independent review after its verify drain and before reconciliation. A read-only reviewer (never a lane owner, never a producer of that wave's artifacts, and never shown the producers' journals or reasoning) returns per-criterion verdicts with cited defects (file:line) against the rubric: (1) correctness vs contract, (2) cross-lane interface consistency, (3) error-handling gaps, (4) unverifiable claims, (5) **environment fidelity** — for each applicable EF item, does the artifact behave the same on a real host? The reviewer actively falsifies privilege/umask boundaries, PATH under sudo, self-matching patterns, boot-time service interactions, bounded waits, refusal observability, real-tool renderings, and provisioning prerequisites; a test that passes only because its shim models the happy path is cited as an environment-fidelity defect with the vacuous test's file:line, and `not applicable` rows and allowlist reasons are second-guessed. A `coder` then writes `state/waves/<n>.review-<k>.md` (`wave`, `status: passed|failed`, rubric table, cited defects) first, then the `D<k>` records citing it; `k = 1 + highest blocked attempt for this wave`. On `failed`, write `blocked-<k>`, halt, and escalate.
- **Review verdict is mechanical:** a review that cites **any** defect of severity ≥ MAJOR returns `status: failed`, regardless of rubric-row outcomes; `passed` with an open ≥ MAJOR citation is an invalid review record (quarantined). MEDIUM/LOW citations may accompany `passed` and are carried in the gate. The review dispositions every open defect sourced to its wave: it confirms a fix by writing `D<j>.fix.md` (a producer may not certify its own fix) or mints a linked `supersedes`/`duplicate_of` record.
- **Criterion→severity rubric:** criterion 4 (an unverifiable claim / a diff-scoped pin or injection without a mutation kill / a vacuous shim) ⇒ **≥ MAJOR**; criterion 3 (error handling that can corrupt or silently lose host state) ⇒ **≥ MAJOR**; criterion 1/2 (a cross-lane contract break that changes a shipped interface) ⇒ **≥ MAJOR**; default ⇒ **MEDIUM**; **MINOR/LOW** only for cosmetic, non-behavioral findings.
- **Independence loosening:** the reviewer MAY read a done record's artifact sections — `## Evidence`, `## EF evidence`, `## Pins & injections`, `## Mutation evidence` — and the repo tests, because these are claims under test, not the producer's reasoning. Producer `logs/`, journals, and reconciliation records stay hidden.
- In a qualifying run, a review record lacking the criterion-5 row is invalid (treated as absent). Every qualifying **single-lane** wave gets one EF-only review `state/waves/<n>.review-<k>.md` containing only the criterion-5 row with `status: passed|failed`; reconciliation stays skipped and a failed EF-only review blocks the gate like a full review.
- Reconciliation then has a `coder` read all lane done records (`assumptions`, `confidence`, `produced`) plus the review verdicts, diff them against `CONTRACT.md`, and write `state/waves/<n>.reconcile-<k>.md` with a decision table (agreements, contradictions, the assumption each contradiction hinges on) and `status: consistent|contradictions-resolved|escalated`. A contradiction resolves only with a cited contract clause or test; otherwise it stays `escalated` and also files an orchestrator escalation.
- Review and reconciliation stages **never create inbox items** — like verify, they cannot block their own gate. Non-qualifying single-lane waves skip both.
- The implicit terminal stage `verify` runs after the last numbered wave gates. With a build policy it runs the full `[verify]` table and writes `state/waves/verify.gate.md` (`status: passed`) or `verify.blocked-<k>.md`. In a qualifying run — with or without a build policy — it also re-executes every lane `## EF evidence` command and records the per-command results in the gate record; a missing test, a different exit code, or a non-existent command fails verify (writing `verify.blocked-<k>.md`) and then writes a `D<k>` citing it. With no build policy and a non-qualifying run it writes `verify.gate.md` with `status: skipped`; no command runs. A re-verify before canary attempt `k≥2` writes `state/waves/verify-<k>.gate.md`.
- A run is DONE only when the last wave gate exists, the terminal verify gate exists with `status: passed|skipped`, and, for a canary-qualifying run, either `canary: opt-out(<reason>)` is recorded or the latest canary attempt has a passed `canary-<k>.gate.md`.

## Canary

- Terminal ladder: waves → verify → **canary** → report. A run is **canary-qualifying** iff it is env-fidelity-qualifying AND its artifacts ship to hosts (deploy/setup entrypoints, unit templates, or a baked image); `canary: required` is the operator's decision to run it, recorded in `RUN.md` before wave 1 spawns.
- `RUN.md` records `canary: required|opt-out(<reason>)|not-required` and `canary_executor: operator|agent`; the default executor is `operator`. Changing either after wave 1 spawns requires an operator message, recorded as append-only `CANARY-CHANGE <utc> <field>=<value> msgid=<id>`.
- **Operator mode (default):** a coder writes `state/canary/runbook.md` (or `runbook-<k>.md` when it changes) with host preparation, the exact entrypoint invocation, success assertions, and the evidence to paste back; the orchestrator halts at `STATUS: NOT DONE (canary: awaiting operator)`. Pasted output is written verbatim to `state/canary/output-<k>.md`; the coder checks it against the runbook without interpreting or editing it. There is no timeout and no automatic opt-out.
- **Agent mode:** requires write-once `state/canary/grant.md` from an operator message with `operator_msgid`, `target`, `credential_profile`, `allowed_commands`, `ttl`, `teardown`. A missing field refuses the spawn. The agent runs nothing outside `allowed_commands`, every command obeys EF5, exceeding `ttl` aborts the attempt as failed (`ttl exceeded`) and still performs teardown; the teardown outcome (instance id + terminated/left) is mandatory evidence.
- Assertions: (1) the changed entrypoint runs as an operator would; (2) declared success criteria hold; (3) every `proof: canary|both` item and every item forced to canary by skipped evidence is checked on the real host; (4) image-touching runs launch a fresh instance from the newly baked AMI and observe an enabled-unit set equal to the EF4 allowlist.
- Records are write-once: `state/waves/canary-<k>.gate.md` (attempt passed) or `state/waves/canary.blocked-<k>.md` (failed or awaiting operator), with frontmatter `stage`, `attempt`, `status`, `executor`, `verify`, `host`, `ami`, `entrypoint`, `evidence`, `teardown`, `defects`, `timestamp`. A passed canary is valid only if `verify:` points at the latest terminal verify gate.
- Failure loop: canary attempt `k` fails → `canary.blocked-<k>.md` (written after `--run` exits 0) → `D<k>` records citing it → halt; operator authorizes `canary.retry-<k>.md`; the orchestrator appends fix wave `N+1` scoped to the cited defect locations, re-runs qualification, and the wave runs the full ladder; terminal verify re-runs as `verify-<k+1>.gate.md`; then canary attempt `k+1`. **Cap: 3 attempts.** After `canary.blocked-3.md` no further wave is appended automatically; the run is NOT DONE and the operator must waive, re-scope, or abandon.
- Report statuses: `STATUS: DONE` (only with a passed canary for the latest attempt or a recorded opt-out); `STATUS: DONE (canary: skipped — operator opt-out: <reason>)`; `STATUS: NOT DONE (canary: awaiting operator)`; `STATUS: NOT DONE (canary: blocked, attempt <k>/3)`. Tagging/publishing before a canary pass or recorded opt-out is the mechanism behind the E1/E2/E5 release cycles; the canary verdict is the recommended pre-tag checkpoint.

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
- A canary-qualifying run is complete only with a passed canary gate for the latest attempt or a recorded operator opt-out. An unanswered canary leaves the run NOT DONE indefinitely; it never silently becomes an opt-out.

## Report

- `REPORT.md` is written once, atomically, with the sentinel. After the `STATUS:` line its first screen carries `env-fidelity: required|not-required — <basis>`, `canary: passed (attempt <k>, executor <operator|agent>)|skipped (opt-out: <reason>)|not-required|awaiting operator|blocked <k>/3`, and the v5 ledger headline `defects: <n> records (<u> unique) — <counts by root_class> — open: <o> (>=MAJOR <m>) — duplicates: <d> — recurrences: <r> — carried: <c> — waived: <w>`.
- New sections: `## Defects` (derived ledger: id, discovered_by, location, severity, root_class, ef_item, why_missed, `duplicate_of`|`supersedes` column, fix|waiver|open), `## Quarantine events` (each `<name>.invalid-<utc>` rename with its reason), and `## Uncovered env-fidelity classes`. The ledger is generated, never hand-edited: **unique** counts chain roots (records with neither link), **duplicates** counts `duplicate_of`, **recurrences** counts `supersedes` (fixes that did not hold), **carried** counts gate-carried MEDIUM/LOW, and **waived** counts waivers.

## Prohibitions

Never commit, push, tag, or deploy. Never edit outside your globs. Never wait or poll. Never rewrite an existing reply file. Never treat `rejected` as a failure. Never spawn subagents. Never write a mutable progress pointer. Never edit `CONTRACT.md` in place. Never let a producer review its own wave. Never show a reviewer the producer's reasoning. Never skip or silently opt out of a canary. Never tag or publish before a canary pass or recorded opt-out. Never downgrade env-fidelity qualification. Never append to a write-once defect or canary record.