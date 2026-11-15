# Waves — 20261115T120000Z-stackctl-7c2f

## Wave 1 — foundations: build/vendor, config, crypto, local modules
depends-on: -
consumes: -
verify: -
| lane | owner | globs |
|---|---|---|
| w1-vendor | coder | MODULE.bazel;BUILD.bazel;third_party/** |
| w1-config | coder | core/config/** |
| w1-crypto | coder | core/crypto/** |
| w1-local | coder | core/ini/**;core/state/**;core/ssh/**;core/knownhosts/** |

## Wave 2 — network seams and CFN templates
depends-on: 1
consumes: core/config/config.h;core/crypto/crypto.h
verify: -
| lane | owner | globs |
|---|---|---|
| w2-awsclient | coder | core/aws/** |
| w2-ddns | coder | core/ddns/**;core/dns/** |
| w2-templates | coder | deploy/** |

## Wave 3 — AWS service modules and CLI common API
depends-on: 2
consumes: core/aws/aws.h;core/config/config.h;core/state/state.h
verify: -
| lane | owner | globs |
|---|---|---|
| w3-cfn | coder | core/cfn/** |
| w3-ec2 | coder | core/ec2/** |
| w3-s3 | coder | core/s3/** |
| w3-ssm | coder | core/ssm/** |
| w3-cliapi | coder | core/cli/cli.h;core/cli/common/** |

## Wave 4 — CLI verbs
depends-on: 3
consumes: core/cli/cli.h;core/cfn/cfn.h;core/ec2/ec2.h;core/s3/s3.h;core/ssm/ssm.h;core/ddns/ddns.h;core/dns/dns.h;core/ssh/ssh.h;core/knownhosts/knownhosts.h;core/state/state.h
verify: -
| lane | owner | globs |
|---|---|---|
| w4-verbs-stack | coder | core/cli/provision/**;core/cli/deploy/**;core/cli/refresh_ami/** |
| w4-verbs-instance | coder | core/cli/launch/**;core/cli/terminate/**;core/cli/status/**;core/cli/startstop/** |

## Wave 5 — wiring, build finalization, tests, docs
depends-on: 4
consumes: core/cli/cli.h;core/main.c
verify: -
| lane | owner | globs |
|---|---|---|
| w5-main | coder | core/main.c;core/cli/dispatch/** |
| w5-build | coder | MODULE.bazel;BUILD.bazel;VERSION |
| w5-tests | coder | tests/** |
| w5-docs | scribe | README.md;AGENTS.md |

## Terminal stage (reserved)
