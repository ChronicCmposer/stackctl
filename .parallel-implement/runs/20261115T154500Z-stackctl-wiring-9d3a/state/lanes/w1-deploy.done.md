---
lane: w1-deploy
wave: 1
status: complete
assumptions: deploy_ops and refresh_ami_ops gained an optional assert_identity seam whose production implementation calls cli_assert_operator_identity, so identity checks are fake-driven in tests; in-band ingress port parsing keeps the existing parse_uint (leading + tolerated)
confidence: high
timestamp: 2026-11-15T20:01:02Z
---
## Evidence
- inbox: empty
- build: bazel --output_base=/tmp/opencode/bazel-w1-deploy build //... -> exit 0
- produced: core/config/config.[ch] (config_ingress_rule[8] + counts + load-time parse); core/cli/cli.h (cli_assert_operator_identity, cli_signal_mark_consumed/consumed, struct aws_ctx); core/cli/common/cli_identity.c and cli_identity_test.c; core/cli/deploy/deploy.c (F2 indexed ingress mapper, F4 DdnsHost/DdnsDomain, F3 guard, F22 pre-publish dry-run bail), deploy_internal.h, deploy_test.c; core/cli/refresh_ami (F3 guard before first SSM read), refresh_ami_internal.h, refresh_ami_test.c; BUILD.bazel targets for //core/cli/common:cli_identity_test.
- disconfirming: did not rebuild the pre-fix tree to capture an executable RED for the deploy F2/F3/F4/F22 cases (they fail pre-fix by construction: no indexed params, no identity seam, dry-run published); slice-boundary CIDR inputs such as "1.2.3.4.5/8" are covered only indirectly. Production PGM (actual STS/S3/CFN) was not exercised; only fake-driven tests and hermetic //... gates.
- tests: bazel --output_base=/tmp/opencode/bazel-w1-deploy test //... -> exit 0 (42/42)
- lint: bazel --output_base=/tmp/opencode/bazel-w1-deploy run //tools/lint:lint -> exit 0
<!-- RECORD-COMPLETE -->
