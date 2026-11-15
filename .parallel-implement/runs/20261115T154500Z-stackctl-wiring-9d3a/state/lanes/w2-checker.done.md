---
lane: w2-checker
wave: 2
status: complete
assumptions: fixture removes both the AmiIdArm64 declaration and its reference so the pre-existing never-referenced rule stays silent; symmetry rule also accepts structural long-form Fn::If in addition to canonical short-form !If
confidence: high
timestamp: 2026-11-15T20:29:09Z
---
## Evidence
- inbox: empty
- build: bazel --output_base=/tmp/opencode/bazel-w2-checker build //deploy/check:template_check //deploy/check:template_check_test -> exit 0
- produced: deploy/check/template_check.c; deploy/check/testdata/bad_infra_ami_asymmetry.yaml; deploy/check/template_check_test.c; deploy/check/BUILD.bazel
- disconfirming: did not run the full //... suite or wave-level verify; TDD RED was observed before the rule existed (1/12 failed, expected 1 got 0), and the fixture is asserted to yield exactly 1 violation while canonical yields 0.
<!-- RECORD-COMPLETE -->
