---
lane: w5-tests
wave: 5
status: complete
assumptions: teardown-failure reporting kept via lstat-check warning in place of system()'s non-zero status; no new RED test added because this retry is a behavior-preserving teardown refactor
confidence: high
timestamp: 2026-11-15T07:40:00Z
---
## Evidence
- inbox: 2 drained (attempt-1 w5-build BUILD-format note replied under
  `inbox/w5-build/w5-tests-20261115T063730Z-tests-build-format-reply.reply.md`;
  w5-tests kh-forget escalation reply present; no new items this attempt)
- build: `bazel build //...` -> exit 0
- test: `bazel test //...` -> exit 0 (40/40 pass, includes
  `//tests/contract:network_seam_test`)
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck 132, buildifier 38,
  shellcheck 3, yaml 8, markdown 2)
- produced: `tests/contract/network_seam_test.c` — replaced
  `system("rm -rf '%s'", root)` with an in-test recursive `remove_tree()`
  (lstat/opendir/readdir/unlink/rmdir) matching the pattern in
  `tests/cli/binary_verb_test.c`, `tests/e2e/lifecycle_test.c` and
  `tests/e2e/stack_test.c`; added `<dirent.h>` and `<limits.h>`; whole temp root
  is still removed and a surviving root still prints the same
  `warning: cleanup failed for <root>` line (Amendment 4: no host tool).
  `grep -n "system(" tests/contract/network_seam_test.c` -> no match.
- disconfirming: did not exercise remove_tree on a read-only/undeletable subtree,
  so the warning path is code-reviewed but not unit-tested; no behavior beyond
  teardown was changed. Transient failures in `//core/cli/dispatch:dispatch_test`
  and `BUILD.bazel # reformat` were w5-main/w5-build mid-edit states outside this
  lane; the final recorded runs are green.
<!-- RECORD-COMPLETE -->
