# Onboarding a new Bazel project to stackctl

Tested against stackctl v0.1.1.

This guide is for a repository maintainer adding stackctl to a **new** Bazel
project. It is the one-time integration path: dependencies, wrapper target,
configuration, templates, provisioning, and the first release/launch. Day-to-day
operator usage lives in the top-level [`README.md`](../README.md); the design
rationale lives in the specification at `/var/lib/opencode/dev/designs/stackctl.md`
(rev 8).

## What stackctl creates

For a project named `<project>` in region `<region>`, stackctl owns:

- an account-global CloudFormation stack `<project>-operator` (instance role and
  profile, operator IAM user, optional CI user and Image Builder roles);
- a regional CloudFormation stack `<project>-infra` (VPC, public subnet, security
  group, retained buckets, optional baked-image pipeline and spot alerts);
- an artifact bucket named `<project>-artifacts-<account>-<region>` and, when
  `BUCKET_MODULES` contains `cert`, a certificate bucket named
  `<project>-certs-<account>-<region>`;
- immutable releases at `s3://<project>-artifacts-<account>-<region>/releases/<tag>/`;
- an instance lifecycle that is **SSH-only**: there is no agent, no control plane,
  and no always-on service on the box.

The bucket names are fixed by the templates. stackctl has no bring-your-own-bucket
option; the only supported shape is the hard-named pair above.

## Prerequisites

Before you start, confirm you have:

- an AWS account and administrative credentials in the `[default]` profile for the
  one-time `provision` run;
- a Bazel 9.x repository using bzlmod (`MODULE.bazel`);
- an existing EC2 key pair and its private key on the operator machine (stackctl
  never creates key pairs);
- a git remote with **annotated** `vX.Y.Z` tags, because `deploy` checks that the
  tag exists on both `HEAD` and `origin`;
- a Namecheap domain and host for DDNS, plus the DDNS password;
- an AMI (or a pinned AMI id) with `sshd`, `aws-cli`, and your runtime; the box
  pulls its bundle from S3 with the instance role;
- systemd on the AMI if you intend to use `start`/`stop`.

Two AWS-side objects are manual by design and are never created by stackctl:

1. The Namecheap **A + Dynamic DNS** record. The DDNS endpoint is update-only, so
   the record must already exist.
2. The SSM SecureString `/<project>/ddns/password` (see
   [Manual AWS steps](#manual-aws-steps)).

## Step 1: depend on stackctl

Add the module dependency and pin it to the repository until stackctl is in a
registry. In `MODULE.bazel`:

```starlark
bazel_dep(name = "stackctl", version = "0.1.1")

git_override(
    module_name = "stackctl",
    remote = "git@git.cmposer.cc:stackctl",
    tag = "v0.1.1",
)
```

`tag` is convenient during evaluation; pin `commit` instead when you need strict
reproducibility. The wrapper target below keeps every operator on this pinned
build, so there is no installed binary to drift.

## Step 2: add the wrapper target

Create `deploy/aws/BUILD.bazel`:

```starlark
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

sh_binary(
    name = "stackctl",
    srcs = ["stackctl.sh"],
    data = ["@stackctl//core/cli/dispatch:stackctl"],
    env = {
        "STACKCTL_BIN": "$(rootpath @stackctl//core/cli/dispatch:stackctl)",
    },
)
```

Create `deploy/aws/stackctl.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
runfiles="${RUNFILES_DIR:?run this target through bazel run}"
exec "$runfiles/$STACKCTL_BIN" --project deploy/aws "$@"
```

The wrapper bakes in `--project deploy/aws`; global flags may still appear before
or after the verb, for example:

```bash
bazel run //deploy/aws:stackctl -- status --json
bazel run //deploy/aws:stackctl -- --region eu-west-1 status
```

## Step 3: write the configuration

The config directory is `deploy/aws/`. It holds:

- `.env` — machine-local, **gitignored**, and never committed;
- `.env.<region>` — an alternate region's config, also machine-local;
- `.env.example` — committed documentation of every key with safe placeholders.

Add this to `.gitignore` (keep the example tracked):

```gitignore
deploy/aws/.env
deploy/aws/.env.*
!deploy/aws/.env.example
```

The allowlist has 36 keys in v0.1.1. Unknown keys are hard errors, and validation
is fail-closed **before any AWS call**. A complete starting `.env.example`:

```dotenv
# Identity
PROJECT=demo
REGION=us-east-1
ARCH=amd64

# AMI policy: pinned | ssm | baked
AMI_POLICY=ssm
AMI_SSM_AMD64=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
# AMI_ID_AMD64 is valid only under AMI_POLICY=pinned.

SPOT_DEFAULT=false
INSTANCE_TYPES_AMD64=g4dn.xlarge
ROOT_VOLUME_SIZE=100
ROOT_VOLUME_TYPE=gp3

KEY_NAME=demo-key
SSH_IDENTITY=/home/operator/.ssh/demo
SSH_USER=ec2-user
SSH_PORT=22
OPERATOR_CIDR=203.0.113.0/24

BUCKET_MODULES=artifact
ENABLE_IMAGE_BUILDER=false
# IMAGE_BUILDER_PARENT_IMAGE is valid only when ENABLE_IMAGE_BUILDER=true.
ENABLE_SPOT_ALERTS=false
# SPOT_ALERT_EMAIL=ops@example.com
# PERMISSIONS_BOUNDARY_ARN=arn:aws:iam::123456789012:policy/operator-boundary

SETUP_ENTRYPOINT=deploy.sh
SERVICE_UNIT=demo.service

INGRESS_TCP=443
INGRESS_UDP=

# DDNS_HOST and DDNS_DOMAIN must be set together.
# DDNS_HOST=play
# DDNS_DOMAIN=example.com
DDNS_ONBOX=false

RELEASE_TARGETS=//app:deploy.tar.gz
RELEASE_PREFIXES=releases/
BAZEL_COMMAND=bazel
```

Rules that catch new maintainers:

- `PROJECT` matches `^[a-z][a-z0-9]+$`. Hyphens are rejected, so the separator in
  `<project>-infra` stays unambiguous. The allowed length is derived per region
  so the longest bucket name fits S3's 63-character limit.
- `AMI_POLICY=pinned` requires `AMI_ID_AMD64`/`AMI_ID_ARM64` for the declared
  architectures; `AMI_ID_*` is an error under `ssm` and `baked`. `ssm` requires an
  absolute `AMI_SSM_*` path. `baked` enables the Image Builder pipeline.
- `ARCH=arm64` requires `INSTANCE_TYPES_ARM64`; `ARCH=both` requires both lists
  and `launch --arch` at run time.
- `BUCKET_MODULES` must include `artifact`; `cert` is optional.
- `ENABLE_SPOT_ALERTS=true` requires `SPOT_ALERT_EMAIL`. `IMAGE_BUILDER_PARENT_IMAGE`
  is valid only when `ENABLE_IMAGE_BUILDER=true`.
- `INGRESS_TCP`/`INGRESS_UDP` are comma lists of `port[:cidr]`; an omitted CIDR
  means `0.0.0.0/0`. Each protocol has at most 8 slots. IPv4 only, no port ranges,
  and the CIDR must not have host bits set. Malformed input fails config validation
  with exit 1 before any AWS call.
- A sibling `.env.<region>` must declare `REGION=<region>` exactly. Plain `.env`
  must not declare a region whose variant file exists.

Copy the example and fill in local values:

```bash
cp deploy/aws/.env.example deploy/aws/.env
$EDITOR deploy/aws/.env
```

### Manual AWS steps

Create the SSM SecureString once per project. stackctl **never writes SSM**, but
`launch` and `status` fail closed when it is missing:

```bash
aws ssm put-parameter \
  --name "/demo/ddns/password" \
  --type SecureString \
  --value "<the Namecheap DDNS password>"
```

The password is per domain, not per host. Leave `DDNS_ONBOX=false` unless you
accept delivering a domain-wide credential to the instance.

Pre-create the Namecheap **A + Dynamic DNS Record** for `DDNS_HOST` on
`DDNS_DOMAIN`. `launch` and `status` verify the record against the authoritative
nameservers and exit 1 with the dashboard instruction when it is absent.

On-box secrets (for example a stream key) are stored the same way: as SSM
SecureStrings under `/<project>/<name>` and fetched by the setup entrypoint at
boot. The instance role grants read on `/<project>/*` only, so store each secret
under that prefix. stackctl never writes these parameters either.

## Step 4: vendor and check the canonical templates

`provision` and `deploy` read the templates from **your repository** at
`<repo-root>/deploy/stackctl-operator.yaml` and
`<repo-root>/deploy/stackctl-infra.yaml`. Copy both files from the stackctl
checkout at the pinned tag and commit them:

```bash
cp /path/to/stackctl/deploy/stackctl-operator.yaml deploy/
cp /path/to/stackctl/deploy/stackctl-infra.yaml deploy/
```

Copying keeps the rendered template reviewable in your repository. Re-copy them
when you upgrade stackctl. Validate the copies with the same structural checker
that gates `TEMPLATE_OVERRIDE` at deploy time:

```bash
bazel run @stackctl//deploy/check:template_check -- \
  operator "$PWD/deploy/stackctl-operator.yaml"
bazel run @stackctl//deploy/check:template_check -- \
  infra "$PWD/deploy/stackctl-infra.yaml"
```

Both commands exit 0 on a valid contract.

Keep the canonical templates unless your project genuinely needs a shape they
cannot express. `TEMPLATE_OVERRIDE` is **infra-only** and is checked fail-closed
before any AWS call; the operator template has no override path. A relative
override is resolved against the repository root, an absolute one verbatim:

```dotenv
TEMPLATE_OVERRIDE=deploy/aws/infra-demo.yaml
```

### Ingress slots: verify the rendered security group

The infra template exposes eight indexed slots per protocol
(`IngressTcpPort0..7`/`IngressTcpCidr0..7`, `IngressUdpPort0..7`/`IngressUdpCidr0..7`).
`deploy` maps each parsed `INGRESS_TCP`/`INGRESS_UDP` rule to one slot, emitting the
port and the CIDR together; slot order follows the config list order. The SSH rule
is separate and conditional, so application slots start at 0.

Each protocol has at most 8 rules. Config validation is strict and runs before any
AWS call: empty items, a trailing comma, IPv6, port ranges, malformed CIDRs, a CIDR
with host bits set, exact duplicate `port:cidr` pairs, and more than 8 rules per
protocol all exit 1 at config load. After the first deploy, confirm the security
group contains the application rules you expect.

## Step 5: provision once

`provision` is account-global and primary-region-only. It uses the `[default]`
admin profile and deploys `<project>-operator` with `CAPABILITY_NAMED_IAM`. It
also ensures the operator user `<project>` (and the CI user `<project>-ci` when
`RELEASE_PREFIXES` is non-empty) has one usable key in `~/.aws/credentials`.

`RELEASE_PREFIXES` is a required key whose value may be empty. An empty value
means "no CI user": on an existing stack, `provision` passes
`EnableCiUser=false`, which **deletes the CI user and invalidates its access
keys**. This is irreversible from the operator's view; `provision` warns in the
change-set summary when it happens.

`RELEASE_PREFIXES` and `BUCKET_MODULES` are collected across **all** `.env.*`
siblings (a union). Clearing a key in the active `.env` alone does not disable the
CI user if a sibling still lists prefixes; clear it in every sibling.

When set, `PERMISSIONS_BOUNDARY_ARN` applies the boundary to the instance role
only. The Image Builder roles, and the infra stack, stay unbounded.

```bash
bazel run //deploy/aws:stackctl -- provision --dry-run
bazel run //deploy/aws:stackctl -- provision
```

Re-run `provision` from plain `.env` after adding a region or changing an
operator-feeding key (`INSTANCE_TYPES_*`, `BUCKET_MODULES`,
`ENABLE_IMAGE_BUILDER`, `RELEASE_PREFIXES`). The operator stack is built from the
union of every sibling variant.

Distributing the CI key to the CI system is a manual step. stackctl mints it; it
does not push it anywhere.

## Step 6: publish the first release

`deploy` is provenance-gated. Create and push an annotated tag first:

```bash
git tag -a v0.1.0 -m "demo v0.1.0"
git push origin v0.1.0
bazel run //deploy/aws:stackctl -- deploy --dry-run
bazel run //deploy/aws:stackctl -- deploy
```

The pipeline is:

1. provenance gate (annotated tag on `HEAD` and on `origin` at the same commit;
   `--allow-dirty` relaxes the dirty tree, not the remote tag);
2. freshness gate (exit 6 when the built artifact is stale or unbuilt);
3. identity guard: the caller ARN must end in `:user/<project>`; an
   `assumed-role` ARN is rejected with exit 3 before any mutation;
4. publish `releases/<tag>/` with `.sha256` sidecars uploaded before objects and
   the manifest last, then verify every member by HEAD and read-back;
5. update `<project>-infra` through a change-set preview, passing the parsed
   ingress slots, `DdnsHost`/`DdnsDomain` when DDNS is configured, the
   spot-alert parameters, and `ImageBuilderParentImage` when configured; record
   `stackctl:release-tag` / `stackctl:release-sha` plus the `ReleaseTag` /
   `ReleaseManifestSha256` parameters;
6. prune, keeping the 10 newest releases and protecting the pinned tag, the
   previous rollback tag, and the just-uploaded tag. A candidate is deleted only
   after a cheap verification of its manifest and members; anything unverifiable
   is kept with a warning.

`deploy --dry-run` is genuinely dry: it runs the read-only gates (including the
identity guard) and stops before publishing, with zero S3 writes and no
change-set creation.

A release tag is immutable once a complete verified manifest exists. Publishing
the same tag again takes the rollback path: verify and record only.

## Step 7: launch, inspect, roll back

```bash
bazel run //deploy/aws:stackctl -- launch
bazel run //deploy/aws:stackctl -- status
bazel run //deploy/aws:stackctl -- status --json
bazel run //deploy/aws:stackctl -- deploy --tag v0.1.0
bazel run //deploy/aws:stackctl -- terminate
```

`launch` runs preflight first (AMI, DDNS record and SSM parameter, non-empty
`OPERATOR_CIDR`, `ssh-keyscan` availability) before any spend. It resolves the
infra stack outputs, launches, waits for an IP, updates and verifies DDNS, pins
the host key in the dedicated store, runs the bundle entrypoint, and replaces the
previous `Project`-tagged instance.

`status` is read-only and lockless. It reports the stack and instance, the pinned
release, DDNS, drift, and preflight health; warnings do not fail it. A
never-deployed project is not an error.

Rollback with `deploy --tag <tag>` restores the **release bundle only**. The
template and parameters always come from the current checkout and config.

## Where to look next

- [`README.md`](../README.md) — every verb, exit code, DDNS/SSM, SSH and
  known-hosts behavior, troubleshooting.
- `README.md` § "Deploy and release workflow" — manifest and pruning contract.
- `README.md` § "On-box bundle contract" — the `STACKCTL_*` environment variables
  your `SETUP_ENTRYPOINT` receives.
- `/var/lib/opencode/dev/designs/stackctl.md` — the authoritative design
  specification (rev 8).

For an existing project moving off the shared shell pipeline, read
[`migration.md`](migration.md) instead of starting from this guide.
