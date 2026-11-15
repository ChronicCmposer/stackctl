# Migrating from the shared `deploy/aws/` shell pipeline

Tested against stackctl v0.1.1.

This guide is for maintainers moving an existing project off the shared
predecessor pattern onto stackctl. The predecessor is the `deploy/aws/` shell
pipeline:

```text
deploy/aws/
  deploy.sh              orchestrator
  launch                 launch helper
  terminate              terminate helper
  provision-account      account bootstrap
  refresh-ami            AMI pin refresher
  common.sh              shared shell library
  <project>-infra.yaml   per-project CloudFormation template
  <project>-operator.yaml
```

The migration is a controlled cutover, not a lift-and-shift. stackctl replaces
the shell entry points with one pinned binary, replaces per-project templates
with two canonical templates (or a checker-gated override), and replaces the old
Bash provenance stack parameters with sha-verified release manifests.

Nothing in this guide lands in a consumer repository. At pilot time each project
gets its own `deploy/aws/STACKCTL_MIGRATION.md` checklist derived from this
playbook; that per-project file is owned by the project, not by stackctl.

## Concept mapping

| Predecessor | stackctl | Notes |
|---|---|---|
| `deploy.sh` | `stackctl deploy` + bundle `SETUP_ENTRYPOINT` | Publishes and records; bundle owns app setup. |
| `launch` | `stackctl launch` | Preflight, AMI, DDNS, host key, setup session. |
| `terminate` | `stackctl terminate` | Sweeps `Project` instances and parks DDNS. |
| `provision-account` | `stackctl provision` | Account-global `<project>-operator` stack. |
| `refresh-ami` | `stackctl refresh-ami` | Requires `AMI_POLICY=pinned`; dual-writes `.env`. |
| `common.sh` | config validation in the binary | Unknown keys are errors; fail-closed before AWS. |
| Per-project CFN templates | Canonical templates in `<repo>/deploy/` | Or an infra-only `TEMPLATE_OVERRIDE`. |
| BYO `DeploymentBucketName` | `<project>-artifacts-<account>-<region>` | No bring-your-own bucket. |
| Bash provenance params | `releases/<tag>/` manifest and stack tags | See the provenance mapping below. |

## Per-resource decision table

| Resource | Decision | Transition rule |
|---|---|---|
| Artifact bucket | **NEW** hard-named bucket; `aws s3 sync` copy | Old bucket read-only until cutover |
| Certificate bucket | **NEW** `<project>-certs-<account>-<region>`; copy | Keep old certs until one renewal succeeds |
| Operator stack / IAM | **FRESH** in one maintenance window | terminate → delete old → provision → relaunch |
| DDNS record | **KEEP** | Lower TTL before the window; raise it after |
| `known_hosts` | **FRESH** dedicated store | `$XDG_STATE_HOME/stackctl/<project>.<region>/known_hosts` |
| Releases | **FRESH** at the next version tag | Old prefixes read-only until cutover completes |
| EC2 key pair | **KEEP** | Reuse `KEY_NAME`/`SSH_IDENTITY` or rotate |
| SSM DDNS secret | **KEEP** or create `/<project>/ddns/password` | Create manually if absent |
| Infra stack | **NEW** `<project>-infra` | Old stack deleted at decommission |
| Instance | **REPLACED** | stackctl replaces the previous `Project` instance |

## Phased runbook

The order below minimizes downtime and keeps a rollback path until the last
phase. Two dependencies are explicit:

- The new infra stack is named `<project>-infra`, so it can coexist with a legacy
  stack named `<project>`.
- `launch` needs an instance profile named `<project>-instance-profile`. Until the
  new operator stack exists, that profile must come from the old operator stack.
  Check this before Phase 2. If it does not match, move the Phase 4 window before
  Phase 2.

### Phase 0 — Prepare (read-only)

1. Inventory the old stack outputs, bucket names, IAM user/profile names, and the
   current release/artifact layout.
2. Record the old template parameters (`BashVersion`, `BashSha256`,
   `SourceSha256`, `PatchSet`) and where each is consumed.
3. Lower the DDNS record TTL in the Namecheap dashboard and wait for the old TTL
   to expire.
4. Freeze new releases on the old pipeline.
5. Confirm the old operator profile name and whether the old instance profile is
   `<project>-instance-profile`.

### Phase 1 — New infra stack alongside the old

1. Add `deploy/aws/BUILD.bazel`, `deploy/aws/stackctl.sh`, `.env`,
   `.env.example`, and the two canonical templates. Follow
   [`onboarding.md`](onboarding.md) Steps 1–4.
2. Use the new project config to point at the **new** bucket names. Do not reuse
   the old bucket names unless you have completed the collision procedure for
   that project.
3. Validate the templates:

   ```bash
   bazel run @stackctl//deploy/check:template_check -- \
     operator "$PWD/deploy/stackctl-operator.yaml"
   bazel run @stackctl//deploy/check:template_check -- \
     infra "$PWD/deploy/stackctl-infra.yaml"
   ```

4. Create the new infra stack with `deploy`. The verb authenticates as the
   `[<project>]` profile. If the old operator user can call CloudFormation and S3,
   use it here; otherwise reorder Phase 4 before this step.
5. Verify the rendered security group. The shared pipeline created no stackctl
   application ingress; the slot mapping is documented below.

### Phase 2 — Launch and terminate cutover

1. Stop using the old `launch`/`terminate` helpers.
2. `stackctl launch` against the new infra stack. The launch replaces the old
   `Project`-tagged instance by default; use `--keep-old` only while validating.
3. Verify:
   - the instance is tagged with the new project;
   - DDNS points at the new IP;
   - the known-hosts store is the dedicated stackctl store;
   - the bundle entrypoint succeeded and the service is healthy.
4. `stackctl terminate` is now the only teardown path. It parks DDNS at
   `0.0.0.0` when the instance is gone, including after a spot interruption.

### Phase 3 — Deploy pipeline cutover

1. Switch release commands to `stackctl deploy` and push an annotated `vX.Y.Z`
   tag to `origin`.
2. Publish the first stackctl release as `releases/<tag>/` with sidecars and a
   manifest. Old unversioned prefixes stay in place and read-only.
3. Point CI at the new release prefix (`RELEASE_PREFIXES`) and update the CI key
   distribution manually.
4. Confirm `status` reports the pinned release as the latest and the old prefixes
   as untouched.

### Phase 4 — Operator-stack maintenance window

This is the only step that removes the old IAM graph.

1. Announce the window; DDNS TTL is already lowered.
2. `stackctl terminate` the instance (or terminate it in the console).
3. Delete the old operator stack. Do **not** do this under a live instance: the
   instance profile and IMDS credentials disappear, and anything that renews TLS
   through the instance role (Caddy's S3 certificate backend, for example) loses
   access.
4. Run `stackctl provision` to create the canonical `<project>-operator` stack
   and refresh the `[<project>]` credentials.
5. `stackctl launch` again on the new infra stack.
6. Verify TLS renewal end to end before deleting any old certificate bucket.
7. Raise the DDNS TTL back to its normal value.

### Phase 5 — Decommission

- Delete the old infra stack and its retained buckets only after a full release
  cycle and at least one certificate renewal have succeeded.
- Remove the old shell entry points and per-project templates from the consumer
  repository.
- Leave the old `releases/` prefixes read-only for one retention period, then
  delete them.
- Record the final state in the project's `deploy/aws/STACKCTL_MIGRATION.md`
  checklist.

## Data-copy procedures

### Artifact bucket

Copy only what the new pipeline needs; old history is not migrated into
`releases/<tag>/`.

```bash
aws s3 sync "s3://<old-bucket>" "s3://<project>-artifacts-<account>-<region>"
```

Verify object counts and a sample of checksums before making the old bucket
read-only.

### Artifact-bucket name collision

If the old bucket is already named `<project>-artifacts-<account>-<region>`, the
new stack cannot create a bucket with that name while the old one exists. Use a
temporary bucket so the hard-named bucket can be created by CloudFormation:

1. `aws s3 sync` the old bucket to
   `s3://<project>-migration-<account>-<region>`.
2. Verify the copy.
3. Empty and delete the old bucket.
4. Create the new infra stack; it now owns the hard-named bucket.
5. Copy the temporary bucket into the new hard-named bucket.
6. Delete the temporary bucket.

This is the movienight landmine described in Appendix B.

### Certificate bucket and Caddy

1. `aws s3 sync "s3://<old-cert-bucket>" \
   "s3://<project>-certs-<account>-<region>"`.
2. Repoint Caddy's S3 backend at the new bucket and prefix. In the bundle, this
   is usually a rendered `Caddyfile` or an env template that names the bucket and
   prefix.
3. Reload Caddy and confirm it can read the existing certificate objects and
   renew them with the instance role.
4. Keep the old bucket until at least one renewal has succeeded. Deleting the old
   operator stack first breaks the instance role and therefore renewal.

## Provenance mapping

The shell pipeline recorded provenance as CloudFormation parameters on the
predecessor stack. stackctl records it in the release manifest and stack tags.

| Old stack parameter | New source of truth | Verification |
|---|---|---|
| `BashVersion` | Annotated `vX.Y.Z` tag and `releases/<tag>/` | `deploy` provenance gate; `STACKCTL_RELEASE_TAG` |
| `BashSha256` | SHA-256 of the entrypoint member | Manifest line; `STACKCTL_MEMBER_SHA` |
| `SourceSha256` | SHA-256 of the source/deploy member | Manifest line plus read-back verification |
| `PatchSet` | One manifest member per patch set (or a patch tarball) | Manifest line plus `STACKCTL_MEMBER_SHA` |

The manifest is `releases/<tag>/release-manifest.txt`, with one member per line
in sha-first form:

```text
<sha256>  <member-name>
```

Every member also has a `<member>.sha256` sidecar uploaded before the object. The
manifest is uploaded last and its SHA-256 is recorded as
`ReleaseManifestSha256` and `stackctl:release-sha` on the stack and resources.
`launch` checks the manifest sha against the stack tag before selecting a member;
the box re-checks the member sha before extraction.

The setup entrypoint receives the provenance through the on-box contract:

| Variable | Meaning |
|---|---|
| `STACKCTL_PROJECT` | Project name. |
| `STACKCTL_REGION` | Region. |
| `STACKCTL_RELEASE_TAG` | Verified release tag. |
| `STACKCTL_MANIFEST_SHA` | Manifest SHA-256 recorded on the stack. |
| `STACKCTL_MEMBER` | Selected bundle object name. |
| `STACKCTL_MEMBER_SHA` | Member SHA-256 the box verifies before extraction. |
| `STACKCTL_ARCH` | Launch architecture. |
| `STACKCTL_VARIANT` | Resolved bundle variant. |
| `STACKCTL_STAGE_DIR` | Staging directory under `/run/`. |
| `STACKCTL_BUCKET_ARTIFACT` | Artifact bucket name. |
| `STACKCTL_BUCKET_CERT` | Certificate bucket name; present only when configured. |
| `STACKCTL_DDNS_PASSWORD_FILE` | `0600` password file; present only when `DDNS_ONBOX=true`. |

If the old entrypoint read `BashVersion`/`SourceSha256`/`PatchSet` directly, move
those values into a bundle member (for example `provenance.env`) and render it
from `STACKCTL_*`. The member is sha-verified end to end, so the entrypoint no
longer trusts a mutable stack parameter.

## Upgrading to v0.1.2

v0.1.2 lets the instance role read project-scoped SSM SecureStrings so on-box
entrypoints can fetch secrets (for example the Twitch stream key for the
strimserver pilot) at boot, without baking secrets into S3 bundles or copying
them over SSH.

- **Instance-role SSM read.** The canonical operator template's `InstanceRole`
  now grants `ssm:GetParameter`/`ssm:GetParameters` on
  `arn:aws:ssm:<region>:<account>:parameter/<project>/*` only. There is no
  `ssm:PutParameter`, no region wildcard, and no wildcard resource. The grant is
  applied on the next `provision`/`deploy` of the operator stack.
- **Consumer action.** Re-copy the vendored canonical
  `deploy/stackctl-operator.yaml` from the stackctl checkout at `v0.1.2` and
  commit it; the next `provision` applies the updated instance role. Store any
  on-box secrets yourself as SSM SecureStrings under `/<project>/<name>` (for
  example `/strimserver/twitch/stream-key`); stackctl never writes SSM.

## Upgrading to v0.1.1

v0.1.1 adds config keys and changes deployed AWS state on the next
`provision`/`deploy` of an existing stack. These land as ordinary change sets (no
extra confirmation gate), but review the summary before applying:

- **App ingress (F2).** `INGRESS_TCP`/`INGRESS_UDP` now create security-group
  rules for the first time. Previously zero application rules were created; check
  the source ranges before applying.
- **Spot alerts (F10).** The spot-alert module and its SNS topic appear or
  disappear according to `ENABLE_SPOT_ALERTS`; `SPOT_ALERT_EMAIL` is passed when
  alerts are enabled.
- **Certificate-bucket IAM (F6).** Operator-stack cert-bucket grants now shrink
  when `BUCKET_MODULES` omits `cert`; previously they were over-granted.
- **CI user deletion (F5).** **WARNING:** clearing `RELEASE_PREFIXES` to an empty
  value makes the next `provision` pass `EnableCiUser=false`, which **deletes the
  CI user and invalidates its access keys**. This is irreversible from the
  operator's view. `provision` prints a one-line change-set-summary warning;
  capture or rotate any CI credentials you still need first. `RELEASE_PREFIXES`
  and `BUCKET_MODULES` are a union across all `.env.*` siblings: clearing the key
  only in the active `.env` does not disable the CI user if a sibling still lists
  prefixes, so clear it in every sibling.
- **DDNS parameters (F4).** `DdnsHost`/`DdnsDomain` are now passed when DDNS is
  configured, so the stack metadata and `DdnsHost` output stop rendering the `-`
  default.

The config allowlist grows from 34 to 36 keys: `IMAGE_BUILDER_PARENT_IMAGE` (valid
only when `ENABLE_IMAGE_BUILDER=true`) and `PERMISSIONS_BOUNDARY_ARN` (an optional
ARN-shaped value). `RELEASE_PREFIXES` stays a required key but now permits an
empty value. `PERMISSIONS_BOUNDARY_ARN` applies to the instance role **only** —
not the CI user, the Image Builder roles, or the infra stack.

## Fixed in v0.1.1

Earlier revisions documented source-level "wiring gaps" where the CloudFormation
templates exposed parameters the CLI never sent. v0.1.1 closes them; this is the
user-visible summary.

- **Bundle setup.** The downloaded bundle is safety-checked and extracted in the
  staging directory before `SETUP_ENTRYPOINT` runs, so a packaged release can
  start. A missing or non-executable entrypoint, or an unsafe member path, is a
  verification failure. The staging directory is removed after the setup status
  is read.
- **Ingress.** Each `INGRESS_TCP`/`INGRESS_UDP` rule populates its
  `IngressTcpPort<i>`/`IngressTcpCidr<i>` (or UDP) slot, up to 8 per protocol.
- **Identity.** `deploy` and `refresh-ami` re-assert the `:user/<project>` caller
  identity before any mutation, including under `--dry-run`; an `assumed-role` ARN
  is rejected with exit 3.
- **Infra parameters.** `DdnsHost`/`DdnsDomain`, the spot-alert parameters, and
  `ImageBuilderParentImage` are now passed from config.
- **CI user.** `provision` sends `EnableCiUser` based on whether `RELEASE_PREFIXES`
  is non-empty, so an empty list deletes the CI user (see the upgrade note above).
- **Certificate IAM.** Operator-stack cert-bucket grants follow `BUCKET_MODULES`.
- **Prune.** A release is deleted only after a cheap manifest and member check; an
  unverifiable release is kept with a warning, and a deploy still succeeds when
  every candidate is unverifiable.
- **Launch.** A setup timeout is a launch failure (exit 4, terminate and DDNS
  restore); the first signal interrupts the setup SSH session and takes the same
  path; exit-7 messages carry the `OPERATOR_CIDR` hint; a failed
  replacement-termination names the surviving instance ids and the
  `terminate --instance-id` command; the AMI-region preflight checks every
  declared architecture.
- **Dry run.** `deploy --dry-run` performs no S3 writes and creates no change set.
- **Template checker.** Under a pinned AMI policy, `AmiIdAmd64` and `AmiIdArm64`
  must both be declared and referenced.
- **Messages.** Ambiguous-tag errors name the tags; pruned-tag rollback lists
  available releases; `refresh-ami --dry-run` prints `KEY: <old> -> <new>` per
  changed key; an interrupted CloudFormation wait says the operation continues
  server-side and suggests `stackctl status`.

## Appendix A — strimserver (pilot)

Project: `strimserver`. The pilot uses the canonical templates and stackctl's
defaults.

### Stack names

| Old | New |
|---|---|
| Infra stack `strimserver` | Infra stack `strimserver-infra` |
| Operator stack `strimserver-operator` | `strimserver-operator` (same name, recreated in the window) |

The operator name already matches stackctl's default. The legacy infra stack has
no `-infra` suffix, so the new stack is a new resource; the old one is deleted at
decommission.

### Old parameters to config keys

| Old | New |
|---|---|
| `ProjectName=strimserver` | `PROJECT=strimserver` |
| controller port `4000` (TCP) | `INGRESS_TCP` includes `4000` |
| SRT port `9000` | `INGRESS_UDP` includes `9000` when the old rule is UDP |
| SSH | Template's conditional `SshIngress` from `OPERATOR_CIDR`; not an app slot |
| instance type | `INSTANCE_TYPES_AMD64` |
| key pair | `KEY_NAME` / `SSH_IDENTITY` |
| EC2 Image Builder pipeline | `ENABLE_IMAGE_BUILDER=true` plus the `BakedImage*` module |
| BYO `DeploymentBucketName` | New hard-named artifact bucket plus `aws s3 sync` |

Slot numbering follows config list order, and the SSH rule is separate, so the
application slots start at `0`:

| List order | TCP slot | UDP slot |
|---|---|---|
| first item | `IngressTcpPort0` / `IngressTcpCidr0` | `IngressUdpPort0` / `IngressUdpCidr0` |
| second item | `IngressTcpPort1` / `IngressTcpCidr1` | `IngressUdpPort1` / `IngressUdpCidr1` |

For example, `INGRESS_TCP=4000` puts the controller on slot 0. If you also list
`443` first, the controller becomes slot 1. SRT media is UDP-based, so `9000`
belongs in `INGRESS_UDP` unless the old security group explicitly opened TCP.
Inspect the old security group before copying the protocol.

The security group is rendered from these slots, so confirm it after the first
deploy.

### Baked image

`ENABLE_IMAGE_BUILDER=true` turns on the `BakedImageComponent`,
`BakedImageRecipe`, `BakedImageInfrastructure`, `BakedImageDistribution`,
`BakedImagePipeline` and publish-role resources. `AMI_POLICY=baked` selects the
pipeline output. The parent image defaults to
`/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64`; set
`IMAGE_BUILDER_PARENT_IMAGE` (valid only with `ENABLE_IMAGE_BUILDER=true`) when
the old pipeline used a different parent.

### Release members

The pilot release is self-contained and sha-verified end to end:

- four OCI image tars;
- controller tar(s);
- ffmpeg tar(s);
- `strimserver.env.template`, rendered by the setup entrypoint.

List each as a `RELEASE_TARGETS` label. The manifest maps every member to its
SHA-256, the operator verifies them at publish and launch, and the box re-checks
the selected member before extraction. The entrypoint reads the template from the
bundle and renders the runtime env; it should not fetch provenance from the old
stack.

## Appendix B — movienight

Project: `movienight`. One GPU instance.

### Configuration

| Old | New |
|---|---|
| Pinned AL2023 DLAMI `AmiId` | `AMI_POLICY=pinned` and `AMI_ID_AMD64` (plus `AMI_ID_ARM64` if needed) |
| GPU instance type | `INSTANCE_TYPES_AMD64` first entry |
| Caddy S3 certificate backend | `BUCKET_MODULES=artifact,cert` |
| Legacy unversioned `releases/` | Fresh `releases/<tag>/` history at the next version tag |
| Infra stack `movienight` | Infra stack `movienight-infra` |

`CertBucketEnabled=true` is derived from `BUCKET_MODULES`; the cert bucket is
`movienight-certs-<account>-<region>`. Copy the certificate data, repoint Caddy,
and keep the old bucket until one renewal succeeds (see
[Certificate bucket and Caddy](#certificate-bucket-and-caddy)).

### Artifact-bucket landmine

The existing movienight artifact bucket already occupies the name
`movienight-artifacts-<account>-<region>`. A new CloudFormation stack cannot
create a bucket with that name, and stackctl does not adopt buckets. The
migration therefore uses the temporary-bucket procedure from
[Artifact-bucket name collision](#artifact-bucket-name-collision). Do not create
the new infra stack before freeing the name.

### Caddy and TLS continuity

Caddy authenticates its S3 certificate backend with the instance role. Never
delete the old operator stack under a live instance: the instance profile and
IMDS credentials disappear, and Caddy loses the ability to read or renew
certificates. The Phase 4 order is mandatory: terminate, delete the old operator
stack, provision, relaunch, then verify renewal.

If Caddy runs in a container on a bridge network, confirm the instance metadata
hop limit is 2; otherwise the container cannot reach IMDS and the certificate
backend fails.

### Provenance and release members

Map the old Bash parameters to manifest members as in
[Provenance mapping](#provenance-mapping). The first stackctl release is
`releases/<tag>/` with the GPU runtime bundle and a `provenance.env` member. The
old unversioned prefix stays read-only until the cutover completes.

## Appendix C — consumer checklist

At pilot time, create `deploy/aws/STACKCTL_MIGRATION.md` in the consumer repository
with these checkboxes filled in for that project:

- [ ] Old stack outputs and bucket names recorded.
- [ ] DDNS TTL lowered; SSM SecureString confirmed.
- [ ] Old operator profile and instance profile names confirmed.
- [ ] Canonical templates copied and checker-clean.
- [ ] `.env`/`.env.example` reviewed; unknown keys removed.
- [ ] New infra stack created; security group verified.
- [ ] First release tagged and published; manifest verified.
- [ ] Launch/terminate cut over; DDNS and known-hosts verified.
- [ ] Operator window completed; TLS renewal verified.
- [ ] Old stacks, buckets, prefixes and scripts decommissioned.
