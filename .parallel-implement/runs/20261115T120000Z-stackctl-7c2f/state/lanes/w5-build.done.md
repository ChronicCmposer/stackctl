---
lane: w5-build
wave: 5
status: complete
assumptions: added direct bazel_dep(bazel_skylib 1.6.1) so BUILD.bazel can use write_file's Starlark FileWriteAction; version_consistency_test.sh is generated shebang-less and run by rules_shell's use_bash_launcher bash via bash's documented ENOEXEC fallback so no host PATH interpreter is resolved; made the sanctioned comment-only edit to third_party/lint/BUILD.shellcheck (outside nominal globs); did not add a checked-in tools/version_consistency.sh because the hermetic in-glob solution made escalation unnecessary; MODULE.bazel.lock is bazel-regenerated/untracked
confidence: high
timestamp: 2026-11-15T07:38:10Z
---
## Evidence
- inbox: 1 drained (w5-main-20261115T073613Z-root-build-reformat request, already satisfied, replied `done` as w5-build-20261115T073751Z-root-build-reformat); all other files are prior `.reply.md` answers
- build: bazel build //... -> exit 0 (85 targets)
- test: bazel test //... -> exit 0 (40 tests, including //:version_consistency_test)
- test: bazel test //:version_consistency_test --nocache_test_results --test_output=all -> exit 0 (executed 1, sandboxed); drift simulation VERSION=0.0.0 -> exit 1 naming the mismatch, VERSION=0.1.0 -> exit 0
- lint: bazel run //tools/lint:lint -> exit 0 (cppcheck 132 files; buildifier 38; shellcheck 3; yaml 8; markdown 2)
- lint: bazel run //tools/lint:buildifier_bin -- -mode=fix -lint=warn -warnings=all BUILD.bazel -> exit 0
- produced: BUILD.bazel (write_file + sh_test use_bash_launcher, no host cat/chmod, no env shebang); MODULE.bazel (bazel_skylib 1.6.1 dep); third_party/lint/BUILD.shellcheck (stale comment now names shellcheck_amd64/shellcheck_arm64)
- disconfirming: rules_shell's launcher shebang is the host-detected `/usr/bin/bash` toolchain path, not a vendored bash binary; shebang-less script execution relies on bash's ENOEXEC fallback (verified here, POSIX/POSIX-shell behavior); amd64 host not exercised (unchanged from prior attempt); version test inspects only the module() `version` line
<!-- RECORD-COMPLETE -->
