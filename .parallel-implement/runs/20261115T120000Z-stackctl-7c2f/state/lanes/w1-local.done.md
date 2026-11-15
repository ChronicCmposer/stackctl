---
lane: w1-local
wave: 1
status: complete
assumptions: state_launch_record is a struct (instance_id, nonce, fqdn, ip, replaced) and kh_binding uses fixed char arrays; sshc_build_argv takes (kind, opts, operands, count) with ssh operands = host + remote command and sshc_exec reports transport failure as ENOTCONN; kh_forget added as the forget op; ini backup name is <path>.bak.<UTCyyyymmddThhMMSSZ>[-n]
confidence: high
timestamp: 2026-11-15T02:03:43Z
---
## Evidence
- inbox: empty
- build: `bazel build //...` -> exit 0
- test: `bazel test //core/... --test_output=errors` -> exit 0 (6 tests pass)
- lint: `bazel run //tools/lint:lint-c` -> exit 0 (28 C files via cppcheck); `bazel run //tools/lint:lint-starlark` -> exit 0 (14 files via buildifier)
- produced: core/ini/ini.h;core/ini/ini.c;core/ini/ini_test.c;core/ini/BUILD.bazel;core/state/state.h;core/state/state.c;core/state/state_test.c;core/state/BUILD.bazel;core/ssh/ssh.h;core/ssh/ssh.c;core/ssh/ssh_test.c;core/ssh/BUILD.bazel;core/knownhosts/knownhosts.h;core/knownhosts/knownhosts.c;core/knownhosts/knownhosts_test.c;core/knownhosts/BUILD.bazel
- disconfirming: ssh/scp argv and exec behavior were exercised with /bin/sh rather than a live sshd/ssh-keyscan, so real OpenSSH option acceptance is not integration-tested; the lock timeout was tested against a second flock description in-process, not two separate processes; no failure injection for ENOSPC/rename errors; the known-hosts store does not parse hashed host fields (it only reads entries it wrote itself).
<!-- RECORD-COMPLETE -->
