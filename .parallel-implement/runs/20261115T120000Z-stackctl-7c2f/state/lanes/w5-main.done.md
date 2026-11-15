---
lane: w5-main
wave: 5
status: complete
assumptions: VERSION resolution order unchanged (STACKCTL_VERSION_FILE override -> RUNFILES_DIR -> argv0.runfiles -> exe.runfiles -> cwd VERSION -> executable-relative ancestors), with bzlmod canonical repo dirs (`stackctl+`, `stackctl+<version>`) added inside each runfiles probe between `_main`/`stackctl` and the ancestor walk; canonical dirs are enumerated from the runfiles root (lexicographically smallest `stackctl+*` wins for determinism) because the version suffix is unknowable a priori, and argv[0]-relative repo dirs are also tried; `-std=gnu23` + `-Wall -Wextra -Werror`
confidence: high
timestamp: 2026-11-15T07:37:44Z
---
## Evidence
- inbox: 3 drained (all previously answered in `inbox/w5-build/`; no unreplied inbound; outbound `w5-main-20261115T073613Z-root-build-reformat` filed for peer-owned root BUILD formatting, resolved by w5-build before final lint)
- build: `bazel build //...` -> exit 0 (52 actions)
- test: `bazel test //...` -> exit 0 (40/40 tests)
- test: `bazel test //core/cli/dispatch:dispatch_test --test_output=errors` RED -> exit 3 (`FAIL dispatch_test.c:347: strstr(text, expected) != NULL` x3 for `stackctl+0.2.0`, `stackctl+0.1.0`, `stackctl+`), then GREEN -> exit 0
- test: `bazel test //core/cli/dispatch:all --test_output=errors` -> exit 0
- lint: `bazel run //tools/lint:lint-c` -> exit 0 (132 files)
- lint: `bazel run //tools/lint:lint` -> exit 0 (c 132 / starlark 38 / shell 3 / yaml 8 / markdown 2)
- consumed-layout demonstration: built binary from cwd `/tmp` with `RUNFILES_DIR=<tmp>/stackctl+0.1.0` -> exit 0 `stackctl v9.8.7 (spec rev 8)`; with `RUNFILES_DIR=<tmp>/stackctl+` -> exit 0 `stackctl v9.8.6 (spec rev 8)`
- produced: core/cli/dispatch/dispatch.c (canonical repo-dir VERSION probing)
- produced: core/cli/dispatch/dispatch.h (resolution docs)
- produced: core/cli/dispatch/dispatch_test.c (parameterised runfiles repo-dir helper + canonical cases)
- disconfirming: real downstream `bazel run //deploy/aws:stackctl` in a separate consuming workspace was not executed (simulated runfiles trees only); manifest-based runfiles (`RUNFILES_MANIFEST_FILE`-only layouts) remain unparsed; canonical-dir enumeration resolves a directory named `stackctl+*` but does not validate that it corresponds to the binary's own repo beyond argv[0]/exe-path derivation.
<!-- RECORD-COMPLETE -->
