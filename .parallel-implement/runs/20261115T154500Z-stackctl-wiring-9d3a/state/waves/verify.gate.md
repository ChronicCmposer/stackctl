---
stage: verify
status: passed
run: 20261115T154500Z-stackctl-wiring-9d3a
timestamp: 2026-11-15T21:41:10Z
output_base: /var/lib/opencode/.cache/opencode/bazel-terminal-verify
bazel: 9.3.2
---

## Terminal verification

Full `[verify]` table from root `AGENTS.md` build-policy. bzlmod-only, no wrapper
declared; unique slot claimed via `--output_base` (not under `/tmp`).

| # | command | exit |
| --- | --- | --- |
| 1 | `bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-terminal-verify build //...` | 0 |
| 2 | `bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-terminal-verify test //...` | 0 |
| 2b | `bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-terminal-verify test //... --nocache_test_results` (supplementary fresh run) | 0 |
| 3 | `bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-terminal-verify run //tools/lint:lint` | 0 |

## Evidence

- build: 87 targets, 883 actions, "Build completed successfully".
- test: 42/42 tests pass (cached); supplementary fresh run 42/42 executed and pass.
- lint: `--mode=all`; lint-c 135 files, lint-starlark 38, lint-shell 3, lint-yaml 11, lint-markdown 4; no violations.
- disconfirming: tests were not run against a host toolchain; results are hermetic Bazel only, per build policy.

<!-- RECORD-COMPLETE -->
