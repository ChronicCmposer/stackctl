# stackctl

`stackctl` is a single static C binary that owns the **operator-side AWS lifecycle** for the
strimserver and movienight deployment family. It replaces the two drifting shell/Python
toolchains with one small, pinned, hermetic build.

It covers:

- `provision` — account bootstrap: the operator stack, IAM users and local credential profiles.
- `deploy` — publish an immutable release, verify it, and update the infra stack.
- `launch` / `terminate` — imperative single-instance lifecycle and DDNS bookkeeping.
- `status` — read-only observability and preflight checks.
- `refresh-ami` — move SSM AMI floats into reviewable config pins.
- `start` / `stop` — service control over SSH.

**Out of scope (v1):** on-box setup. The deployment bundle ships its own entrypoint
(`SETUP_ENTRYPOINT`, default `deploy.sh`). `stackctl`'s contract ends at delivering a verified
bundle to a running instance and invoking that entrypoint with the documented environment.

## Why a single binary

- **One artifact.** No per-repo bash/Python toolchain, no AWS SDK, no `aws-cli` on the operator
  path. Static musl builds for Linux amd64 and arm64.
- **Minimal supply chain.** libcurl, mbedTLS, yyjson and c-ares are vendored as sha256-pinned
  archives and built from source with a hermetic zig-cc toolchain. There is no network fetch at
  build time.
- **Stable automation contract.** Plain-text output by default, `--json` on every verb, and a
  small fixed exit-code table that scripts may branch on.

## Requirements

An operator workstation needs:

- Linux on amd64 or arm64.
- Bazel 9.x (bzlmod only). The configured `BAZEL_COMMAND` (default `bazel`) is used for the
  deploy freshness gate.
- `ssh`, `scp` and `ssh-keyscan` on `PATH`. `stackctl` execs OpenSSH; it never links a libssh.
  `ssh-keyscan` is required for launch host-key pinning.
- A checkout of the consuming repository, because the freshness gate and release provenance run
  with the repository root as their working directory.
- AWS credentials in `~/.aws/credentials`: `[default]` for `provision`'s admin calls and
  `[<project>]` for project-identity verbs. `provision` writes these profiles.
- A pre-existing EC2 key pair (`KEY_NAME`) and its private key (`SSH_IDENTITY`). `stackctl`
  never creates or stores private keys.
- For DDNS projects, a pre-existing Namecheap dynamic-DNS record and the SSM SecureString
  described in [DDNS and SSM setup](#ddns-and-ssm-setup).

`stackctl status` checks these prerequisites; there is no separate doctor verb.

## Build and run

The repository is bzlmod-only and builds with the hermetic toolchain pinned in `MODULE.bazel`.
No host compiler, linter or test runner is required.

```bash
# Build the static binary.
bazel build //:stackctl

# Print the release tag (VERSION) and the design-spec revision.
bazel run //:stackctl -- --version

# Run a verb from a consuming checkout, against that checkout's config directory.
bazel run //:stackctl -- --project deploy/aws status
```

There is no installed binary. Consumers expose a wrapper target such as
`bazel run //deploy/aws:stackctl` (or a thin script that execs it), so the binary in use is
always the repository-pinned bzlmod build. `//:stackctl` is an alias for the real binary target
`//core/cli/dispatch:stackctl`.

`--version` prints the release tag from the committed `VERSION` file plus the design-spec
revision. A consumed-build invocation may run with a working directory that is neither this
checkout nor the runfiles tree, so the tag is resolved in a fixed order:

1. `STACKCTL_VERSION_FILE`, when set. It is authoritative: an unreadable path renders `unknown`.
2. The Bazel runfiles tree, located through `$RUNFILES_DIR`, then `<argv0>.runfiles`, then
   `<executable>.runfiles`. Within that root it probes `_main/VERSION`, `stackctl/VERSION`, the
   bzlmod canonical repo directories `stackctl+` and `stackctl+<version>` (for example
   `stackctl+0.1.0`), then the binary's ancestor directories.
3. `VERSION` in the process working directory.
4. `VERSION` in the executable's ancestor directories.

A committed `VERSION` found in any of these locations wins over the `unknown` fallback, so the
documented consumed-build invocation reports the release tag even though its working directory
is the consumer checkout. `VERSION` is the single source of truth for the release identity;
`MODULE.bazel` repeats the module version because bzlmod cannot read a workspace file while
evaluating the module, and the hermetic `//:version_consistency_test` fails `bazel test //...`
when the two drift.

## Quick start

```bash
# 1. Create the machine-local config from the committed example.
cp deploy/aws/.env.example deploy/aws/.env
$EDITOR deploy/aws/.env

# 2. Bootstrap the account once. Uses the [default] admin profile.
bazel run //:stackctl -- --project deploy/aws provision

# 3. Publish a release and update the infra stack.
bazel run //:stackctl -- --project deploy/aws deploy

# 4. Launch an instance.
bazel run //:stackctl -- --project deploy/aws launch

# 5. Inspect stack, instance, DNS and drift status.
bazel run //:stackctl -- --project deploy/aws status
```

## Documentation

Two maintainer-oriented guides complement this operator reference:

- [Onboarding a new Bazel project](docs/onboarding.md) — add stackctl to a
  greenfield repository: module dependency, wrapper target, configuration,
  templates, provisioning, first release and first launch.
- [Migrating from the `deploy/aws/` shell pipeline](docs/migration.md) — the
  per-resource cutover plan for the shared predecessor, with the strimserver and
  movienight appendices.

Both guides are versioned and name the stackctl release they were tested against.

## Configuration

### Location, committed versus local

Each consuming repository carries its project configuration in `deploy/aws/`:

- `deploy/aws/.env` — the live, **machine-local, gitignored** config for the primary region.
- `deploy/aws/.env.<region>` — the config for another region, for example `.env.eu-west-1`.
- `deploy/aws/.env.example` — committed documentation of every key with placeholder values.

A new operator copies `.env.example` and fills in local values, including `SSH_IDENTITY`.
Config changes that should be reviewed travel through `.env.example`.

`--project` is a **path only** in v1, with no name shorthand. The file format is flat
`KEY=VALUE` with comments, blank lines and optional quoting; there is no interpolation.

### One config file = one region

`--region <name>` loads `deploy/aws/.env.<name>` and is a hard error (exit 1) when the file is
absent. Without `--region`, plain `.env` is loaded. There is no ambient environment-variable
inference.

If `.env.<r>` exists, it must declare `REGION=<r>` exactly. Plain `.env` must not declare a
`REGION` for which a sibling variant exists. Two config files can therefore never share a state
namespace or lock.

**`provision` is primary-only.** It runs only from plain `.env`; `provision --region ...` exits 1.
The account-global operator stack is built from the union of every sibling variant's
operator-feeding keys (`INSTANCE_TYPES_*`, `BUCKET_MODULES`, `ENABLE_IMAGE_BUILDER`,
`RELEASE_PREFIXES`). Adding a region or an instance type therefore requires re-running
`provision` from the primary config.

### Path resolution and repository root

A relative `--project` is resolved against `$BUILD_WORKING_DIRECTORY` when Bazel sets it, otherwise
against the process working directory. Do not assume that the working directory under `bazel run`
is the runfiles tree or the source checkout: it varies with the invocation. `BUILD_WORKING_DIRECTORY`
records where `bazel run` was invoked, which is what keeps a relative `--project` stable.

The repository root is found by walking up from the resolved config directory to the first
ancestor containing `MODULE.bazel`. All `git` and `BAZEL_COMMAND` invocations run with the
repository root as their working directory. A missing repository root, or a config file whose
real path lies outside it (for example, a symlink escaping the checkout), exits 1.

### Validation

Validation is fail-closed at startup, before any AWS call:

- Unknown keys are errors, not warnings.
- Required keys are checked per declared architecture and module.
- `PROJECT` must match `^[a-z][a-z0-9]{1,N}$`. Hyphens are rejected so the separator in
  `<project>-*` resource names is unambiguous. `N` is derived so the longest bucket name fits
  S3's 63-character limit in the configured region.
- Cross-key rules are enforced, for example `ARCH=arm64` requires `INSTANCE_TYPES_ARM64`,
  `ENABLE_SPOT_ALERTS=true` requires `SPOT_ALERT_EMAIL`, `ENABLE_IMAGE_BUILDER=true` requires
  `IMAGE_BUILDER_PARENT_IMAGE` (an EC2 AMI id or a full SSM parameter ARN), and DDNS keys are
  required together.
- Ingress rules are fully parsed at config load. Each item is `port` or `port:cidr`; IPv4 only,
  no port ranges, strict CIDR (host bits must be clear), no exact duplicate `port:cidr` pairs,
  and at most 8 rules per protocol. Malformed input exits 1 before any AWS call.
- Booleans, ports and volume sizes are range-checked.

### Keys

| Key | Required | Meaning |
|---|---|---|
| `PROJECT` | yes | Project name; no hyphens; prefixes all AWS resources and names both stacks. |
| `REGION` | yes | Primary region for the infra stack and launches. One file = one region. |
| `ARCH` | yes | `amd64`, `arm64`, or `both`. When `both`, `launch --arch` is required. |
| `SPOT_DEFAULT` | yes | `true`/`false`; `launch --spot`/`--no-spot` override. |
| `AMI_POLICY` | yes | `pinned` (AmiId only), `ssm` (public SSM float), or `baked` (Image Builder). |
| `AMI_ID_AMD64` | pinned | Pinned AMI id for amd64. |
| `AMI_ID_ARM64` | pinned | Pinned AMI id for arm64. |
| `AMI_SSM_AMD64` | ssm | Public SSM parameter name for amd64; also read by `refresh-ami` under pinned. |
| `AMI_SSM_ARM64` | ssm | Public SSM parameter name for arm64; also read by `refresh-ami` under pinned. |
| `INSTANCE_TYPES_AMD64` | yes | Comma list of allowed amd64 instance types; the first entry is the default. |
| `INSTANCE_TYPES_ARM64` | arm64 | Comma list of allowed arm64 instance types. |
| `ROOT_VOLUME_SIZE` | yes | Root EBS volume size in GiB (`1`-`65536`). |
| `ROOT_VOLUME_TYPE` | no | Root EBS type; default `gp3`. Encryption and delete-on-termination are invariants. |
| `KEY_NAME` | yes | Pre-existing EC2 key pair name. `stackctl` never creates key pairs. |
| `SSH_IDENTITY` | yes | Path to the private key for `KEY_NAME`. |
| `SSH_USER` | no | SSH login user; default `ec2-user`. No launch flag. |
| `BUCKET_MODULES` | yes | Comma list drawn from `artifact` and `cert`. |
| `ENABLE_IMAGE_BUILDER` | yes | `true`/`false`; toggles Image Builder roles and the pipeline. |
| `IMAGE_BUILDER_PARENT_IMAGE` | builder | Required when builder on: AMI id or full SSM ARN; no default. |
| `ENABLE_SPOT_ALERTS` | no | `true`/`false` (default false); adds the SNS spot-interruption alert module. |
| `SPOT_ALERT_EMAIL` | spot alerts | Required when `ENABLE_SPOT_ALERTS=true`; SNS email target. |
| `PERMISSIONS_BOUNDARY_ARN` | no | IAM permissions-boundary ARN, applied to the instance role only. |
| `SETUP_ENTRYPOINT` | yes | Bundle entrypoint; default `deploy.sh`. |
| `SERVICE_UNIT` | start/stop | systemd unit name used by `start`/`stop`; no derivation convention. |
| `SSH_PORT` | yes | Operator SSH port; default `22`. |
| `OPERATOR_CIDR` | yes | SSH source CIDR; empty omits the SSH rule entirely. |
| `IP_ECHO_URL` | no | Default `https://checkip.amazonaws.com`; fetched only by `status`. |
| `INGRESS_TCP` | yes | Comma list of `port[:cidr]` TCP application ingress rules. |
| `INGRESS_UDP` | yes | Comma list of `port[:cidr]` UDP application ingress rules. |
| `DDNS_HOST` | ddns | Namecheap DDNS host; case-sensitive; the record must already exist. |
| `DDNS_DOMAIN` | ddns | Namecheap domain; case-sensitive. |
| `DDNS_ONBOX` | no | `true`/`false` (default false). When true, the DDNS password is delivered to the box. |
| `RELEASE_TARGETS` | yes | Comma list of Bazel labels locating the deployment artifact(s). |
| `BAZEL_COMMAND` | no | Bazel invocation; default `bazel`. Honors wrapper scripts. |
| `RELEASE_PREFIXES` | yes | S3 prefixes the CI reader user may read. Required key; may be empty (no CI user). |
| `TEMPLATE_OVERRIDE` | no | Path to a local CFN template replacing the canonical one. |

Because `stackctl`'s lifecycle is SSH-only, `launch`, `start` and `stop` fail closed (exit 1)
when `OPERATOR_CIDR` is empty.

`INGRESS_TCP`/`INGRESS_UDP` rules map in list order to the infra template's indexed slots: rule
`i` populates `IngressTcpPort<i>` and `IngressTcpCidr<i>` (or `IngressUdpPort<i>` and
`IngressUdpCidr<i>`). Each protocol allows at most 8 rules, and the SSH rule is separate. The
template is IPv4-only, and a port is always emitted together with its CIDR.

### Credentials profiles

Credential selection is fixed per verb class, not a chain:

- `provision` admin calls use only the `[default]` profile.
- Every project-identity verb uses only the `[<project>]` profile.

All `AWS_*` environment variables are stripped or ignored, so a stray shell export cannot
select the identity. `provision` also mints the CI profile `[<project>-ci]` when configured.
Distributing that CI key into the CI system's secret store is a **manual operator step**.

## CLI reference

```text
stackctl [global flags] <verb> [verb flags]
```

Global flags may appear before or after the verb.

| Flag | Meaning |
|---|---|
| `--project <dir>` | Config directory. Required for every verb; `--help`/`--version` need none. |
| `--region <name>` | Load `.env.<name>`; absent file is exit 1. |
| `--json` | Emit one JSON document on stdout. Errors still go to stderr. |
| `--yes`, `-y` | Answer yes to the `apply? [y/N]` prompt. Required on non-TTY stdin. |
| `--dry-run` | Preview without applying. Supported by `provision`, `deploy`, `refresh-ami`. |
| `--lock-timeout <sec>` | Wait for the project lock; expiry is a usage error (exit 1). |
| `--help`, `-h` | Print global or per-verb usage. |
| `--version` | Print the `VERSION` tag and design-spec revision. |

Exit codes are a stable scripting contract:

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Usage or config error, including lock-timeout expiry; no side effects. |
| 2 | AWS API error after retries, or another operation already in progress. |
| 3 | Verification failure: sha mismatch, identity guard, provenance or immutable tag. |
| 4 | Instance launch failed and the instance was terminated. |
| 5 | Teardown or cleanup incomplete; the message names what was left behind. |
| 6 | Freshness gate: the deployment artifact is stale or unbuilt. |
| 7 | SSH transport failure: refused, auth rejected or host-key mismatch. The instance exists. |

`status` uses its own subset: 0 for pass or warnings, 1 for a preflight failure, 2 for AWS
errors, and 3 for an identity-guard mismatch.

### provision

```text
provision [--rotate] [--rotate-ci]
```

Deploys the account-global `<project>-operator` CFN stack in the primary region using the
`[default]` admin profile and `CAPABILITY_NAMED_IAM`. It then ensures the operator user
`<project>` (and, when `RELEASE_PREFIXES` is non-empty, the CI user `<project>-ci`) has one
usable key in `~/.aws/credentials`.

`RELEASE_PREFIXES` is a required key whose value may be empty. An empty value means no CI
user: on an existing stack, `provision` passes `EnableCiUser=false`, which **deletes the CI
user and invalidates its access keys** (irreversible from the operator's view). `provision`
emits a one-line change-set-summary warning on that transition. When
`PERMISSIONS_BOUNDARY_ARN` is set, it applies to the instance role only, not the CI user or
the Image Builder roles.

Re-runs are create-or-update. An update is previewed with a change set and requires
confirmation unless `--yes` is given; `--dry-run` prints the preview and exits. After a decline
or dry run, the change set is deleted and a leftover empty `REVIEW_IN_PROGRESS` shell stack is
removed.

| Flag | Meaning |
|---|---|
| `--rotate` | Mint a new key for the operator user. |
| `--rotate-ci` | Mint a new key for the CI user. |

Key lifecycle keeps a one-key invariant: stale keys are deleted before a new one is created.
The previous local key is deleted only after the new key passes the identity check. A CI key is
never auto-minted while any key exists in IAM; use `--rotate-ci`.

```bash
bazel run //:stackctl -- --project deploy/aws provision --dry-run
bazel run //:stackctl -- --project deploy/aws provision
```

Exit codes: 0, 1, 2, 3.

### deploy

```text
deploy [--tag <vX.Y.Z>] [--allow-dirty] [--skip-build]
```

1. **Provenance gate.** `HEAD` must carry an annotated `vX.Y.Z` tag that also exists on
   `origin` at the same commit. A dirty tree is rejected unless `--allow-dirty`; this does not
   bypass the remote-tag check. Multiple release tags on `HEAD` exit 1.
2. **Freshness gate.** Bazel locates the built artifacts and errors without compiling if they
   are stale (exit 6). `--skip-build` skips only this gate.
3. **Identity guard.** The caller ARN must end in `:user/<project>`; an `assumed-role` ARN is
   rejected with exit 3 before any mutation. The guard runs under `--dry-run` too.
4. **Publish.** Build a manifest, upload `.sha256` sidecars before objects and the manifest
   last, then verify every member by S3 HEAD and read-back.
5. **Record and update.** Update the `<project>-infra` stack with a change-set preview, then
   record the release in stack tags `stackctl:release-tag` / `stackctl:release-sha` and in the
   `ReleaseTag` / `ReleaseManifestSha256` parameters referenced from resource metadata. The
   change set also carries the parsed ingress slots, `DdnsHost`/`DdnsDomain` when DDNS is
   configured, and the spot-alert parameters; `ImageBuilderParentImage` is passed verbatim
   when `ENABLE_IMAGE_BUILDER=true` (where it is required).
6. **Prune.** Keep the 10 newest releases, protecting the stack-pinned tag, the previous
   rollback tag and the just-uploaded tag. A candidate is deleted only after a cheap check of
   its manifest and members; anything unverifiable is kept with a warning.

| Flag | Meaning |
|---|---|
| `--tag <vX.Y.Z>` | Roll back to an existing release, or redeploy the current tag. |
| `--allow-dirty` | Allow a dirty working tree. |
| `--skip-build` | Skip the freshness gate; never overrides tag immutability. |

A release tag is immutable once a complete verified manifest exists. Publishing the same tag
again takes the rollback path: verify and record only. `--skip-build` against an immutable tag
exits 3.

`--dry-run` is genuinely dry: it runs the read-only provenance, freshness and identity checks
and stops before publishing, with zero S3 writes and no change-set creation. If every prune
candidate is unverifiable, nothing is pruned and the deploy still exits 0 with a summary line.

```bash
bazel run //:stackctl -- --project deploy/aws deploy
bazel run //:stackctl -- --project deploy/aws deploy --tag v1.4.2
bazel run //:stackctl -- --project deploy/aws deploy --tag v1.4.2 --allow-dirty
```

Rollback restores the **release bundle only**. The template and parameters always come from the
current checkout and config, and the preview states this explicitly. `deploy --tag <current>`
is the documented infra/config-only redeploy.

Exit codes: 0, 1, 2, 3, 5, 6.

### refresh-ami

```text
refresh-ami [--dry-run]
```

Requires `AMI_POLICY=pinned`; under `ssm` or `baked` it exits 1. It re-asserts the
`:user/<project>` caller identity before the first SSM call and rejects an `assumed-role` ARN
with exit 3. It resolves the current SSM float for every declared architecture and dual-writes
`AMI_ID_AMD64` / `AMI_ID_ARM64` into both the local config and its committed `.env.example`
counterpart. The write replaces only the matching `KEY=` line and is atomic, preserving
comments and key order.

`--dry-run` prints `KEY: <old> -> <new>` for each changed key (unchanged keys are silent)
without writing. Missing keys or a missing example file exit 1; nothing is appended or created.
The new pin reaches launches only after `deploy` moves it onto the stack, so the verb ends by
printing "run deploy to apply".

```bash
bazel run //:stackctl -- --project deploy/aws refresh-ami --dry-run
bazel run //:stackctl -- --project deploy/aws refresh-ami
```

Exit codes: 0, 1, 2.

### launch

```text
launch [--arch <amd64|arm64>] [--instance-type <type>] [--variant <go|c>]
       [--spot|--no-spot] [--keep-on-failure] [--keep-old]
       [--instance-timeout <sec>] [--ssh-timeout <sec>] [--setup-timeout <sec>]
```

Runs preflight first — AMI resolution, DDNS record and SSM parameter presence, non-empty
`OPERATOR_CIDR`, and `ssh-keyscan` availability — all before any spend. It resolves the infra
stack outputs (missing stack exits 1), reads the DDNS secret, calls `RunInstances`, waits for an
IP, updates and verifies DDNS, verifies the host key, binds known-hosts, extracts the bundle in
a staging directory, runs the setup entrypoint from the bundle root, then replaces the previous
Project-tagged instance.

| Flag | Meaning |
|---|---|
| `--arch` | `amd64` or `arm64`; required when `ARCH=both`, must match a single-valued `ARCH` if given. |
| `--instance-type <type>` | Must be in the arch allowlist; default is its first entry. |
| `--variant` | `go` or `c`; select the manifest member when more than one matches the arch. |
| `--spot` / `--no-spot` | Override `SPOT_DEFAULT`. |
| `--keep-on-failure` | Do not terminate the new instance on failure. |
| `--keep-old` | Skip replacement of the previous instance. |
| `--instance-timeout <sec>` | Instance-ready waiter; default 300. |
| `--ssh-timeout <sec>` | SSH connect retry window; default 300. |
| `--setup-timeout <sec>` | Entrypoint execution; default 1800. |

Capacity errors such as `InsufficientInstanceCapacity` exit 2 with no silent fallback. The
message suggests `--no-spot` or another allowlisted instance type. Spot requests omit
`MaxPrice`, so AWS applies the on-demand cap.

On failure the new instance is terminated unless `--keep-on-failure`, and DDNS is restored per
the restore-target rule: the snapshot IP only if it still belongs to a running Project-tagged
instance, otherwise the record is parked at `0.0.0.0`. Cleanup failure takes precedence and
exits 5. A setup timeout is a launch failure: the instance is terminated (unless kept), DDNS is
restored, and the verb exits 4. The first signal during setup interrupts the SSH session and
takes the same path. SSH transport failures exit 7 but still terminate the instance unless
kept.

```bash
bazel run //:stackctl -- --project deploy/aws launch
bazel run //:stackctl -- --project deploy/aws launch --arch arm64 --no-spot
bazel run //:stackctl -- --project deploy/aws launch --keep-on-failure --setup-timeout 3600
```

Exit codes: 0, 1, 2, 3, 4, 5, 7.

### terminate

```text
terminate [--instance-id <id>]
```

With no flag, sweeps every `Project=<project>` instance in a live state, waits until each is
`terminated`, then parks the DDNS A record at `0.0.0.0` and verifies it against the authoritative
nameservers. This is deliberate: after a spot interruption the instance is gone but DNS may
still point at its released IP, so run `terminate` to park it. Zero matches plus a successful
park is exit 0. A termination waiter timeout or park failure exits 5.

With `--instance-id <id>`, terminates exactly one instance, which must carry the `Project` tag
(else exit 1), and parks DNS only if the record currently points at that instance's public IP.
This is the remedy named by launch's exit-5 messages.

```bash
bazel run //:stackctl -- --project deploy/aws terminate
bazel run //:stackctl -- --project deploy/aws terminate --instance-id i-0123456789abcdef0
```

Exit codes: 0, 1, 2, 5.

### status

```text
status [--json]
```

Read-only and lockless. Reports the infra stack status and key parameters; Project-tagged
instances, their states and launch AMIs; the pinned release versus the latest release; the DDNS
record versus the actual instance IP; and known-hosts bindings.

It also runs the prerequisite checks (Bazel, SSH tools, credentials profile, state directory,
key pair and identity file), the AMI-region preflight, and these health checks:

- Orphan instances whose launch nonce matches no completed launch record.
- Missing release members or manifest-less garbage prefixes.
- AMI drift between config pins and the stack's `AmiId` under `pinned`.
- DDNS record and SSM parameter presence; parked state.
- Operator public IP outside `OPERATOR_CIDR` (using `IP_ECHO_URL`).
- Multiple live launch nonces younger than one hour, indicating concurrent operator machines.

Warnings do not fail the verb. A never-deployed project is not an error: status exits 0 with
absent fields while still surfacing a broken operator environment.

`--json` carries a `schema_version` and never contains secrets. Errors go to stderr, so stdout
stays parseable.

```bash
bazel run //:stackctl -- --project deploy/aws status
bazel run //:stackctl -- --project deploy/aws status --json
```

Exit codes: 0, 1, 2, 3.

### start / stop

```text
start [--instance-id <id>] [--trust-new-host-key]
stop  [--instance-id <id>] [--trust-new-host-key]
```

SSH-execs `sudo systemctl start|stop <SERVICE_UNIT>`. Requires `SERVICE_UNIT`. With
`--instance-id`, acts on exactly one Project-tagged instance (else exit 1). Without it, exactly
one running Project instance is required; zero or multiple exits 1 and names the candidates.
The verb holds the project lock.

If the dedicated known-hosts store has no binding for the target, the host key is re-verified
from console output plus `ssh-keyscan`. If console fingerprints are unavailable, the verb exits
7 rather than silently trusting a new key; `--trust-new-host-key` explicitly allows the scanned
key.

```bash
bazel run //:stackctl -- --project deploy/aws start
bazel run //:stackctl -- --project deploy/aws stop
bazel run //:stackctl -- --project deploy/aws start --instance-id i-0123456789abcdef0
```

Exit codes: 0, 1, 2, 7.

## Deploy and release workflow

Releases are immutable S3 prefixes:

```text
s3://<project>-artifacts-<acct>-<region>/releases/<vX.Y.Z>/
  <artifact>            # one or more deployment bundles
  <artifact>.sha256     # sidecar, uploaded before its object
  release-manifest.txt  # member-to-sha256 map; the commit marker
```

The manifest is the commit marker. A prefix without a complete verified manifest is garbage by
definition: consumers do not trust it, and pruning ignores it until it is older than 24 hours.

Verification happens at every hop:

1. The operator verifies uploads by S3 HEAD and read-back.
2. `launch` downloads only the manifest, checks its sha against the stack's
   `stackctl:release-sha` tag, and selects the arch/variant member.
3. The box pulls that member from S3 with the instance role and checks the operator-supplied
   sha before extraction. The box never trusts a downloaded `.sha256` sidecar.
4. The bundle entrypoint runs; a non-zero status is a launch failure and its last 150 output
   lines are copied to the operator's stderr.

Pruning keeps the 10 newest releases by manifest `LastModified`, protects the pinned, previous
rollback and just-uploaded tags, and never expires `releases/` through an S3 lifecycle rule.

## On-box bundle contract

The bundle is pulled **on-box from S3** with the instance role, never pushed by the operator.
`launch` verifies the manifest and member sha operator-side, then the box checks the passed
member sha with `sha256sum --check` before extraction. `aws-cli` must therefore exist on the
AMI, including baked AMIs. The bundle is staged in `/run/stackctl-setup.<nonce>/` (tmpfs, 0700)
and extracted there after a path-safety precheck; the entrypoint then runs from the bundle
root. A missing or non-executable `SETUP_ENTRYPOINT`, or an unsafe archive member path, is a
verification failure (rc 3). The staging directory is removed after the setup status is read.
The entrypoint's NVMe phase 0 runs inside the bundle, not in stackctl.

The entrypoint runs as one `ssh -T` session through `sudo env -u BASH_ENV ...` with every value
shell-quoted. The binary exports these variables:

| Variable | Meaning |
|---|---|
| `STACKCTL_PROJECT` | Project name. |
| `STACKCTL_REGION` | Region. |
| `STACKCTL_RELEASE_TAG` | Verified release tag recorded on the stack. |
| `STACKCTL_MANIFEST_SHA` | Manifest sha recorded on the stack. |
| `STACKCTL_MEMBER` | Selected bundle object name. |
| `STACKCTL_MEMBER_SHA` | Member sha the box verifies before extraction. |
| `STACKCTL_ARCH` | Launch architecture. |
| `STACKCTL_VARIANT` | Resolved bundle variant. |
| `STACKCTL_STAGE_DIR` | Staging directory under `/run/`. |
| `STACKCTL_BUCKET_ARTIFACT` | Artifact bucket name. |
| `STACKCTL_DDNS_PASSWORD_FILE` | `0600` password path; present only when `DDNS_ONBOX=true`. |

The remote wrapper writes the entrypoint's real status to `<STACKCTL_STAGE_DIR>/rc` and prints
`STACKCTL_RC=<n>` as its final line. stackctl trusts that sentinel over ssh's own exit status. If
ssh exits 255 without a sentinel, it reconnects once to read the rc file; an absent file exits 7
with "remote status unknown".

App-specific setup (drivers, Caddy, NVMe selection, service wiring) belongs entirely to the
bundle. When `DDNS_ONBOX=true`, the operator scp path is used only for the small DDNS password
file; otherwise no DDNS secret reaches the instance.

## DDNS and SSM setup

The Namecheap DDNS endpoint is **update-only**: it cannot create, delete or read a record. Two
manual steps are therefore required once per project.

### 1. Pre-create the record

In the Namecheap dashboard, create an **A + Dynamic DNS Record** for `DDNS_HOST` on
`DDNS_DOMAIN`. `launch` and `status` verify its presence by querying the domain's authoritative
nameservers; a missing record exits 1 with this dashboard instruction. Host and domain are
case-sensitive.

The record TTL is Namecheap's "Automatic" (1800 s) and cannot be changed through the DDNS
endpoint. Recursive caches may serve a stale IP for up to about 30 minutes after a launch or
park. `stackctl`'s correctness checks always query the authoritative nameservers directly.

### 2. Create the SSM SecureString

```bash
aws ssm put-parameter \
  --name "/<project>/ddns/password" \
  --type SecureString \
  --value "<the Namecheap DDNS password>"
```

`stackctl` never writes this parameter; `status` and `launch` check that it exists and exit 1
with the command to run when it does not.

The DDNS password is **per domain**, not per host: every project sharing a domain shares the
secret, and anyone holding it can repoint any host on that domain. That is why `DDNS_ONBOX`
defaults to `false` and the password normally stays operator-side. Enabling `DDNS_ONBOX=true`
is an explicit acceptance of that domain-wide exposure; it delivers the password to the
instance as a `0600` file and sets `STACKCTL_DDNS_PASSWORD_FILE`.

Under `AMI_POLICY=ssm`, the public AMI floats named by `AMI_SSM_AMD64` / `AMI_SSM_ARM64` must
also exist in the project region. Under `baked`, the Image Builder pipeline publishes
`/<project>/ami/baked/latest`.

## SSH and known_hosts behavior

`stackctl` always connects by the instance's **public IP**, never by FQDN, so a DNS race cannot
reach a previous instance. Every connection uses `-o HostKeyAlias=<instance-id>`, and the
dedicated store is `$XDG_STATE_HOME/stackctl/<project>.<region>/known_hosts`. The operator's
`~/.ssh/config` stays in effect (so `ProxyJump` works), but every safety-relevant option is
overridden explicitly:

`BatchMode=yes`, `IdentitiesOnly=yes`, `-i <SSH_IDENTITY>`, `UpdateHostKeys=no`,
`ControlMaster=no`, `ControlPath=none`, `UserKnownHostsFile=<dedicated store>`,
`StrictHostKeyChecking=yes`, `HostKeyAlias=<instance-id>`, `ServerAliveInterval`,
`ServerAliveCountMax`, `Port=<SSH_PORT>` and `User=<SSH_USER>`.

Host-key pinning at launch:

1. Poll EC2 console output for cloud-init's SSH host-key fingerprint block.
2. Run `ssh-keyscan -t ed25519 <public-ip>` and compute the SHA256 fingerprint.
3. If the console block is present, the fingerprints must match; a mismatch exits 3.
4. If the console block never appears, that first connection uses
   `StrictHostKeyChecking=accept-new` with a warning (TOFU). All later connections use `yes`.

Binding rules: a new instance id claiming an FQDN replaces an old binding with a warning. The
same instance id presenting a changed host key is a hard error and is never auto-healed.

## State, locks and audit trail

All persistence lives under `$XDG_STATE_HOME/stackctl/` (default `$HOME/.local/state`), mode
0700, namespaced per project and region:

```text
stackctl/
  <project>.<region>.lock    # exclusive flock held by every verb except status
  <project>.<region>/
    known_hosts              # dedicated host-key store
    bindings                 # instance-id -> host key, FQDN, IP
    launches                 # launch records
    release-history.log      # release tags, append-only
    operations.log           # verb, redacted args, AWS calls, outcome (0600)
```

One coarse lock is held for the entire duration of every mutating verb (`provision`, `deploy`,
`launch`, `terminate`, `refresh-ami`, `start`, `stop`). `status` is lockless. `--lock-timeout`
bounds the wait; expiry exits 1.

Every locked verb appends to `operations.log`. Secrets are never written there. `status` does
not write to it.

## Troubleshooting

### Exit 5: cleanup incomplete

The message names what was left behind. Common remedies:

- Instance termination timed out: run `terminate --instance-id <id>`.
- DDNS restore or park failed: update the record manually to the IP named in the message.

Cleanup steps are attempted independently; the primary failure's exit code stands unless a
cleanup step itself fails, in which case cleanup wins with exit 5.

### Exit 7: SSH transport failure

The instance exists but is unreachable: connection refused, authentication rejected, or host-key
mismatch. Verify that your current public IP is inside `OPERATOR_CIDR`; `stackctl status`
checks and reports this. A host-key mismatch is also a security signal: a changed key for the
same instance id is never healed automatically.

### Capacity errors

`InsufficientInstanceCapacity`, `MaxSpotInstanceCountExceeded` and `SpotMaxPriceTooLow` exit 2
without switching purchase model, instance type or availability zone. The infra stack has one
public subnet and therefore one AZ. Retry with `--no-spot` or another allowlisted instance type.

### Clock skew

A SigV4 `403` that looks like a credential failure may be clock skew. `stackctl` prints the
local clock versus the server `Date` delta and suggests NTP. It never adjusts the clock itself.

### Stale DNS after launch or terminate

Namecheap's 1800 s TTL means recursive resolvers can lag after a change. `stackctl` verifies
against the authoritative nameservers, so its checks can be correct while a client still sees
the old address. Wait for cache expiry; do not "fix" it by repointing the record.

### CloudFormation stack states

- `CREATE_COMPLETE`, `UPDATE_COMPLETE`, `UPDATE_ROLLBACK_COMPLETE`: proceed.
- `REVIEW_IN_PROGRESS` with zero resources: proceed with a new create change set.
- `ROLLBACK_COMPLETE` after a failed create: delete the stack, then re-run.
- `UPDATE_ROLLBACK_FAILED`: run `aws cloudformation continue-update-rollback` manually.
- `DELETE_FAILED`: the message names the resources; resolve them manually.
- Any `*_IN_PROGRESS`: exit 2, another operation is in progress; wait and re-run.

`stackctl` never auto-deletes or auto-recovers a stack.

### Orphan instances

A crash mid-launch leaves a Project-tagged instance whose launch nonce matches no completed
launch record. `status` detects it; it never terminates automatically. The next successful
launch replaces it, `terminate` sweeps it, or use `terminate --instance-id <id>`.

### Rebuilding after a deliberate teardown

Buckets use `DeletionPolicy: RetainExceptOnCreate`, so stack deletion keeps them. A deliberate
rebuild is a manual sequence: delete the stack, empty and delete the retained buckets, then
recreate the stack fresh. Otherwise CloudFormation fails with `BucketAlreadyOwnedByYou`.

## Architecture overview

```text
core/
  config/       .env parsing, validation, repo-root resolution
  crypto/       SHA-256, HMAC-SHA256, SigV4 (hand-rolled)
  ini/          ~/.aws/credentials upsert with timestamped backup
  state/        XDG state dir, lock, bindings, launch/release/audit records
  ssh/          ssh(1)/scp(1) argv builder and sentinel-aware exec
  knownhosts/   dedicated host-key store
  aws/          single AWS HTTP seam: curl + SigV4, retries, waiters
  cfn/ ec2/     request builders and response parsers over core/aws
  s3/ ssm/
  iam/          STS/IAM Query calls over the same seam
  ddns/         Namecheap update over curl (its own seam)
  dns/          c-ares queries to authoritative nameservers
  cli/          cli_ctx, shared output/confirm helpers, verb implementations
  main.c        thin entry point
deploy/         canonical CFN templates + structural template checker
tests/          integration, contract and link-seam tests
third_party/    vendored dependency BUILD overlays
tools/lint/     hermetic lint drivers and in-repo Markdown/YAML checkers
```

Module rules:

- `config` is the only module that reads files at startup; downstream modules take typed values.
- `aws` is the single AWS-API seam. Only `cfn`, `ec2`, `s3`, `ssm` and `iam` build requests over
  it.
- The only other network users are `ddns`, `dns`, and `status`'s single `IP_ECHO_URL` fetch.
  A link-time test asserts that no other translation unit references socket symbols.
- `ssh` never links a libssh; it execs OpenSSH with a controlled argv and the dedicated store.
- `state` owns all persistence and the per-project-per-region lock.

## Development

Build, test and lint use Bazel only; the repository's `[verify]` build policy is the authoritative
command list. The canonical commands are:

```bash
bazel build //...
bazel test //...
bazel build --config=lint-c //... && bazel run //tools/lint:lint
```

Run an individual linter while iterating:

```bash
bazel build --config=lint-c //...      # cppcheck per-target aspect over C sources
bazel run //tools/lint:lint-starlark   # buildifier over BUILD/MODULE/*.bzl
bazel run //tools/lint:lint-shell      # shellcheck over shell scripts
bazel run //tools/lint:lint-yaml       # yaml_check over *.yaml/*.yml
bazel run //tools/lint:lint-markdown   # markdown_check over *.md
```

Lint is part of every verification step. C sources are checked by a per-target aspect, so each
target's cppcheck action runs in parallel and caches independently; the aggregate target covers
the remaining linters. Vendored upstream sources are never linted, only the overlay files under
`third_party/`. Tooling is fetched and pinned by `MODULE.bazel`: cppcheck is built from its pinned
release source, while buildifier and shellcheck are pinned prebuilt release binaries
(sha256-verified, fetched per-CPU via Bazel `select()`). The `markdown_check` and `yaml_check` C
programs live in-repo. No host-installed compiler, linter or test runner is used.

Conventions:

- **C23.** All stackctl-authored C code compiles as `-std=gnu23` (or `-std=c23` where no
  extensions are needed). Vendored upstream sources keep their own flags.
- **TDD.** Each behavior is built RED → GREEN → REFACTOR. The failing test is written first;
  the implementation makes it pass; refactoring keeps the suite green without changing behavior.
- **Error model.** Library functions return 0 or a non-zero errno-style code with out-params
  for results. Only CLI verb layers call `exit`-class helpers.
- **Naming.** Public symbols are prefixed with the module name (`config_`, `crypto_`, `sigv4_`,
  `aws_`, `cfn_`, `ec2_`, `s3_`, `ssm_`, `iam_`, `ddns_`, `dns_`, `ini_`, `state_`, `sshc_`,
  `kh_`, `cli_`).
- **Streams.** stdout is reserved for CLI output, including the single `--json` document.
  Diagnostics, warnings and prompts go to stderr.
- **JSON.** yyjson only.
- **Supply chain.** Every dependency is vendored and sha256-pinned; there is no network fetch at
  build time.
