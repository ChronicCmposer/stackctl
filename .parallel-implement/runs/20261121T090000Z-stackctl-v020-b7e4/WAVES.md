# Waves — 20261121T090000Z-stackctl-v020-b7e4

## Wave 1 — preflight
depends-on: -
consumes: -
verify: -
| lane | owner | globs |
| w1-preflight | coder | - |

## Wave 2 — checker testdata (test-first)
depends-on: 1
consumes: -
verify: -
| lane | owner | globs |
| w2-tests | coder | deploy/check/testdata/** |

## Wave 3 — implementation
depends-on: 2
consumes: deploy/check/testdata
verify: test
| lane | owner | globs |
| w3-checker | coder | deploy/check/** |
| w3-config | coder | core/config/* |
| w3-provision | coder | core/cli/provision/* |
| w3-template | coder | deploy/stackctl-operator.yaml;deploy/stackctl-infra.yaml;deploy/BUILD.bazel |

## Wave 4 — consumers and release docs
depends-on: 3
consumes: -
verify: test
| lane | owner | globs |
| w4-cli-tests | coder | core/cli/deploy/*;core/cli/refresh_ami/*;core/cli/common/* |
| w4-e2e | coder | tests/** |
| w4-docs | coder | docs/**;README.md;VERSION;MODULE.bazel |

## Wave 5 — fix waived checker defects
depends-on: 4
consumes: deploy/check/template_check.c,deploy/check/template_check_test.c,deploy/check/testdata
verify: test
| lane | owner | globs |
| w5-checker | coder | deploy/check/** |

## Wave 6 — close checker residuals
depends-on: 5
consumes: deploy/check/template_check.c,deploy/check/template_check_test.c,deploy/check/testdata
verify: test
| lane | owner | globs |
| w6-checker | coder | deploy/check/**;docs/migration.md |

## Terminal stage (reserved)

basis: appended fix wave for waived D7 (LOW) and D8 (MAJOR, duplicate_of D7) and carried D9 (MEDIUM); operator authorization msgid operator-20261121T065750Z-retry-cap-5 (operator chat operator-chat-2026-11-21-retry-cap-5). Single-lane is permitted because this is an appended fix wave for cited defects, not the N-wave run structure (waves 1–4 already satisfy the ladder).
