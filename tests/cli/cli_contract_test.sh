#!/usr/bin/env bash
#
# cli_contract_test.sh — process-level exit-code contract for the built binary.
#
# Exercises the frozen spec §4 exit codes that need no AWS: usage/config errors
# are exit 1, while --help/--version succeed. No network, no credentials.
set -euo pipefail

binary="${1:?usage: cli_contract_test.sh <stackctl-binary> <version-file>}"
version_file="${2:?usage: cli_contract_test.sh <stackctl-binary> <version-file>}"

fail() {
    printf 'cli_contract_test: %s\n' "$1" >&2
    exit 1
}

expect_exit() {
    local want="$1"
    shift
    local got=0
    "$@" >/dev/null 2>&1 || got=$?
    if [ "$got" -ne "$want" ]; then
        fail "expected exit $want, got $got: $*"
    fi
}

# Help and version are success and never require a project.
expect_exit 0 "$binary" --help
expect_exit 0 "$binary" --version

version_output="$("$binary" --version)"
expected_version="$(head -n1 "$version_file")"
case "$version_output" in
    *"$expected_version"*) ;;
    *) fail "--version did not report the VERSION file ($expected_version)" ;;
esac

# No verb and unknown verbs are usage errors (exit 1).
expect_exit 1 "$binary"
expect_exit 1 "$binary" frobnicate

# `--project` is mandatory for every verb.
expect_exit 1 "$binary" status

# A missing config directory is a usage error.
expect_exit 1 "$binary" --project "$(mktemp -d)/absent" status

# An invalid config (unknown key, fail-closed) is a usage error before any AWS
# call, including for the lockless status verb.
root="$(mktemp -d)"
mkdir -p "$root/deploy/aws"
: >"$root/MODULE.bazel"
cat >"$root/deploy/aws/.env" <<'EOF'
PROJECT=demo
REGION=us-east-1
ARCH=amd64
SPOT_DEFAULT=false
AMI_POLICY=pinned
AMI_ID_AMD64=ami-0123456789abcdef0
INSTANCE_TYPES_AMD64=g4dn.xlarge
ROOT_VOLUME_SIZE=100
KEY_NAME=demo-key
SSH_IDENTITY=/home/operator/.ssh/demo
BUCKET_MODULES=artifact
ENABLE_IMAGE_BUILDER=false
SETUP_ENTRYPOINT=deploy.sh
SSH_PORT=22
OPERATOR_CIDR=
INGRESS_TCP=443
INGRESS_UDP=
RELEASE_TARGETS=//app:deploy.tar.gz
RELEASE_PREFIXES=releases/
TOTALLY_UNKNOWN=1
EOF
expect_exit 1 "$binary" --project "$root/deploy/aws" status

printf 'cli_contract_test: ok\n'
