---
stage: verify
status: passed
timestamp: 2026-11-21T08:56:32Z
---
## Commands
| command | exit |
|---|---|
| `bazel build //...` | 0 |
| `bazel test //... --test_output=errors --nocache_test_results` | 0 |
| `bazel build --config=lint-c //...` | 0 |
| `bazel run //tools/lint:lint` | 0 |
| `./bazel-bin/deploy/check/template_check operator deploy/stackctl-operator.yaml` | 0 |
| `./bazel-bin/deploy/check/template_check infra deploy/stackctl-infra.yaml` | 0 |

## EF evidence
not applicable — run is env-fidelity not-required

## Waves
Waves 1–6 gates present: `1.gate.md`, `2.gate.md`, `3.gate.md`, `4.gate.md`, `5.gate.md`, `6.gate.md`.
<!-- RECORD-COMPLETE -->
