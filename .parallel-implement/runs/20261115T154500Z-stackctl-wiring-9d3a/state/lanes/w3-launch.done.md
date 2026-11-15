---
lane: w3-launch
wave: 3
status: complete
assumptions: launch keeps an instance_config snapshot with no arch_list, so launch_arch_list expands the validated ARCH exactly as config_arch_list does; the F16 hint is one stderr line appended after each exit-7 primary diagnostic
confidence: high
timestamp: 2026-11-15T20:56:19Z
---
## Evidence
- inbox: empty
- build: bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-w3-launch build //... -> exit 0
- test: bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-w3-launch test //... -> exit 0 (42 tests pass); focused //core/cli/launch:launch_test --nocache_test_results -> exit 0
- lint: bazel --output_base=/var/lib/opencode/.cache/opencode/bazel-w3-launch run //tools/lint:lint -> exit 0
- produced: core/cli/launch/launch.c; core/cli/launch/launch_test.c
- disconfirming: real remote shell execution of the reconnect reader was not run (the command string is asserted); per-arch SSM policy path exercised only through pinned stack parameters, not a live SSM parameter fetch
<!-- RECORD-COMPLETE -->
