# Waves — 20261115T154500Z-stackctl-wiring-9d3a

## Wave 1 — S1 blockers + launch interruptibility
depends-on: -
consumes: -
verify: build,test,lint
fixes: w1-launch=F1,F8,F9; w1-deploy=F2,F3,F4,F22

| lane | owner | globs |
| --- | --- | --- |
| w1-launch | coder | core/cli/launch/**;core/ssh/**;core/cli/dispatch/**;core/cli/startstop/** |
| w1-deploy | coder | core/cli/deploy/**;core/cli/config/**;core/cli/common/**;core/cli/refresh_ami/**;core/cli/cli.h |

## Wave 2 — remaining S2
depends-on: 1
consumes: -
verify: build,test,lint
fixes: w2-provision=F5,F6,F11-config,F13; w2-deploy=F7,F10,F11-pass; w2-checker=F12

| lane | owner | globs |
| --- | --- | --- |
| w2-provision | coder | core/cli/provision/**;core/cli/config/** |
| w2-deploy | coder | core/cli/deploy/**;core/s3/** |
| w2-checker | coder | deploy/check/** |

## Wave 3 — S3 diagnostics
depends-on: 2
consumes: -
verify: build,test,lint
fixes: w3-launch=F16,F17,F18,F21; w3-deploy-prov=F14,F15,F20; w3-refresh=F19

| lane | owner | globs |
| --- | --- | --- |
| w3-launch | coder | core/cli/launch/** |
| w3-deploy-prov | coder | core/cli/deploy/**;core/cli/provision/** |
| w3-refresh | coder | core/cli/refresh_ami/** |

## Wave 4 — guides & docs
depends-on: 3
consumes: -
verify: lint
fixes: w4-docs=guides update per design section 1/5

| lane | owner | globs |
| --- | --- | --- |
| w4-docs | coder | docs/**;README.md |

## Terminal stage (reserved)
