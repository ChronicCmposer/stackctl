# CONTRACT — 20261115T154500Z-stackctl-wiring-9d3a

Frozen shared interfaces for all lanes. Lanes code ONLY against this contract, never against guessed peer behavior. Changes only via escalation to inbox/orchestrator/; the orchestrator appends `## Amendment <k>` sections. Companion design: /var/lib/opencode/dev/designs/stackctl-wiring-fixes.md (authoritative for per-fix behavior); companion spec: stackctl.md rev 8.

## C1. cli.h additive exports (owner: w1-deploy)
Add to core/cli/cli.h (additive only; existing declarations immutable):
- file-scope forward declaration `struct aws_ctx;`
- `int cli_assert_operator_identity(struct aws_ctx *aws, const char *project);`
- `void cli_signal_mark_consumed(void);`
- `int cli_signal_consumed(void);`

Semantics:
- cli_assert_operator_identity: calls iam_get_caller_identity. STS failure -> returns CLI_EXIT_AWS (2) with a stderr diagnostic. ARN not ending in `:user/<project>` -> returns CLI_EXIT_VERIFY (3) naming expected vs actual ARN. An `arn:aws:sts::...:assumed-role/...` ARN -> CLI_EXIT_VERIFY (3) with a dedicated assumed-role message. Exact suffix match `:user/<project>` mirroring the five existing guards (instance_runtime.c:149-186, status.c:488-521, provision.c:624-637 style) -> 0. Account-id verification is out of scope (documented weakness).
- cli_signal_mark_consumed / cli_signal_consumed: a single consumed flag alongside the existing signal bookkeeping in the "Signals" section implementation (core/cli/common). dispatch.c: when a verb returns OK but a signal was received AND !cli_signal_consumed(), keep today's CLI_EXIT_AWS mapping (dispatch.c:117-124); when consumed, honor the verb's returned exit code verbatim.
Implementation site: core/cli/common (new file or the file implementing cli_signal_*; register in its BUILD.bazel).

## C2. ssh abort hook (owner: w1-launch)
In the core/ssh public header:
- `typedef int (*sshc_abort_fn)(void *user);`
- `void sshc_set_abort_hook(sshc_abort_fn fn, void *user);`
Checked in sshc run_once's existing wait loop (50 ms poll granularity); on abort reuse the existing terminate_group escalation (SIGTERM -> 5 s -> SIGKILL, ssh.c:391-423) and return EINTR. Mirrors the aws_set_abort_hook pattern.

## C3. config additions
Wave 1 (owner w1-deploy) — ingress parsed at config load, malformed -> exit 1:
- `typedef struct { unsigned port; char cidr[19]; } config_ingress_rule;` (port 1..65535; cidr NUL-terminated IPv4 CIDR string, e.g. "0.0.0.0/0")
- fields on stackctl_config: `config_ingress_rule ingress_tcp[8]; size_t ingress_tcp_count;` and `config_ingress_rule ingress_udp[8]; size_t ingress_udp_count;`
- Parse rules per design F2: trim whitespace per item; reject empty items and trailing comma; empty list = no rules; item = `port` or `port:cidr`, omitted cidr -> `0.0.0.0/0`; reject exact (port,cidr) duplicates; same port with different cidrs allowed; IPv6 rejected with a clear message; no port ranges; strict IPv4 CIDR (4 octets 0-255, prefix 0-32, host-bits-set rejected); >8 per protocol (TCP and UDP independent) -> exit 1 naming protocol, count, and the 8-slot limit.
Wave 2 (owner w2-provision) — new optional keys:
- `IMAGE_BUILDER_PARENT_IMAGE` (valid only when ENABLE_IMAGE_BUILDER=true, mirroring the AMI_ID_*-under-pinned cross-key validation) and `PERMISSIONS_BOUNDARY_ARN` (ARN-shaped string when present). known_keys[] grows 34 -> 36.
- fields on stackctl_config: `const char *image_builder_parent_image;` and `const char *permissions_boundary_arn;` (NULL when unset).
- F5: RELEASE_PREFIXES stays required-present, empty value permitted; has_ci = non-empty value.
If the existing stackctl_config idiom differs materially from these field shapes, escalate; do not silently redesign.

## C4. deploy ops seam (owner: w2-deploy)
Add to core/cli/deploy/deploy_internal.h alongside verify_release (line 47), copying its exact parameter list: `int (*verify_release_cheap)(void *ud, ...);`. Production impl: GET the manifest, parse each `<sha256>  <member>` line, HEAD each member (existence + size consistency); verified iff all HEADs succeed. prod_prune: a candidate prefix is deletable only after cheap-verify returns 0; any failure keeps the release with a one-line warning (tag + reason); verification only for candidates past the protections, capped at 20 per run (remainder deferred with a summary line); if every candidate fails, nothing is pruned and deploy still exits 0 with per-tag warnings plus an "N releases kept: unverifiable" summary. Byte-exact verify_release is unchanged for publish provenance.

## C5. CFN param emission conventions
- F2 (w1-deploy): for each parsed rule i, emit BOTH `IngressTcpPort<i>` and `IngressTcpCidr<i>` (resp. UDP); unused slots are not passed.
- F4 (w1-deploy): pass `DdnsHost` and `DdnsDomain` from config iff DDNS_HOST is configured; pass nothing when unset.
- F10 (w2-deploy): pass `EnableSpotAlerts=true|false` always; `SpotAlertEmail` iff alerts are on.
- F11 (w2-deploy): pass `ImageBuilderParentImage` iff config sets it (field per C3).
- F5 (w2-provision): pass `EnableCiUser=true` + `ReleasePrefixes` iff has_ci, else `EnableCiUser=false`; one-line change-set-summary warning on the true->false transition.
- F6 (w2-provision): pass `CertBucketEnabled=true|false` computed from certs membership in BUCKET_MODULES (same membership test as deploy.c:1814-1818).
- F13 (w2-provision): pass `PermissionsBoundaryArn` iff set.

## C6. F1 generated setup-script fragments (owner: w1-launch)
After the sha check succeeds, rc-driven (no set -e):
1. path-safety precheck: `sudo tar -tf "$d/<member>"` — reject if any member path is absolute or contains a `..` component -> rc=3;
2. extract: `sudo tar --no-same-owner --no-overwrite-dir -xf "$d/<member>" -C "$d"` — failure -> rc=3;
3. entrypoint check: if `"$d/<entrypoint>"` is not a file or not executable -> rc=3, message naming SETUP_ENTRYPOINT;
4. run: `(cd "$d" && sudo env STACKCTL_PROJECT="$STACKCTL_PROJECT" ... "./<entrypoint>") >"$d/setup.log" 2>&1` — the env var list generated from the SAME single source that builds the ssh prefix at launch.c:467-520 (including optional STACKCTL_BUCKET_CERT / STACKCTL_DDNS_PASSWORD_FILE when present) so the two lists cannot drift.
SETUP_ENTRYPOINT stays a bundle-root-relative path. Cleanup, rc-file, reconnect-once, and the 150-line tail are unchanged (F21 appends post-read staging removal).

## C7. Exit mappings
- F8 (w1-launch): setup-ssh ETIMEDOUT -> launch_fail(..., CLI_EXIT_LAUNCH) (terminate + DDNS restore); ENOTCONN -> 7; other transport errors -> 7.
- F9 (w1-launch): EINTR from the setup ssh call -> launch_fail(..., CLI_EXIT_LAUNCH) AND cli_signal_mark_consumed(); start/stop map EINTR to their existing failure path and also mark consumed.
- F22 (w1-deploy): deploy --dry-run bails BEFORE publish_release (zero S3 writes, no change-set creation); the F3 identity guard still runs before the bail.

## C8. S3 diagnostics (tests assert key tokens only, never exact wording)
F14: ambiguous-tag error names the offending tags. F15: pruned-tag rollback lists available releases (bounded, single S3 page). F16: every exit-7 launch path appends an OPERATOR_CIDR hint (factor a ssh_hint helper). F17: replacement-termination failure lists surviving instance ids + the exact `terminate --instance-id` command. F18: AMI-region preflight mirrors deploy's per-arch loop (deploy.c:1629-1659) over the config arch list before RunInstances. F19: refresh-ami --dry-run prints `KEY: <old> -> <new>` per changed key, unchanged keys silent. F20: interrupted-CFN-wait diagnostics in deploy.c and provision.c append "continues server-side; run `stackctl status`". F21: the reconnect-once reader appends `sudo rm -rf "$d" || true` AFTER successfully reading $d/rc — best-effort; cleanup failure must not change the reported rc.

## C9. Per-lane acceptance criteria
- Every fix has a RED->GREEN test that fails against the pre-fix tree (write it first).
- Every build/test claim carries the exact command and its exit code, run through Bazel per AGENTS.md build-policy; claim a unique Bazel slot per lane; never a bare tool invocation.
- Lint must pass for touched files.
- Error model per AGENTS.md: library functions return 0/errno; only verb layers map to exit codes; stdout clean; diagnostics on stderr.
- C23; module-symbol prefixes; no keys/flags invented beyond the two contracted config keys.

## C10. Identity guard call sites (owner: w1-deploy, fix F3)
- deploy: once, immediately after the production aws client is created, before publish_release and before the dry-run bail (bucket naming's own read-only STS may precede it).
- refresh_ami: before the first SSM GetParameter (production_resolve).
- Existing per-verb guards in provision/status/instance verbs are NOT refactored onto the helper in this run.

## Amendment 1 — config module glob interpretation

Citing escalation `w2-provision-20261115T201819Z-config-glob`: the `WAVES.md` lane globs reading `core/cli/config/**` (w1-deploy, w2-provision) are a manifest typo. The config module lives at `core/config/**` (AGENTS.md "Repository layout": `core/config/ .env parsing, validation, repo-root resolution`). Effective write surface for both lanes is `core/config/**`; the directory `core/cli/config/` does not exist. No other glob is affected. Orchestrator decision, 2026-11-15.
