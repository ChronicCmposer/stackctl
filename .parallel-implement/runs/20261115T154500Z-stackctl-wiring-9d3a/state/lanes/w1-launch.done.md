---
lane: w1-launch
wave: 1
status: complete
assumptions: ssh abort hook is module-level per C2 and installed by launch and start/stop around the setup/session ssh call; env var list generated from one visitor (literal and reference emitters) so prefix and in-script re-injection cannot drift
confidence: high
timestamp: 2026-11-15T19:50:11Z
---
## Evidence
- inbox: empty
- build: bazel build //... -> exit 0
- produced: core/ssh/ssh.h; core/ssh/ssh.c; core/ssh/ssh_test.c; core/cli/launch/launch.c; core/cli/launch/launch_test.c; core/cli/dispatch/dispatch.c; core/cli/dispatch/dispatch_test.c; core/cli/startstop/startstop.c; core/cli/startstop/startstop_test.c
- disconfirming: no live-AWS or on-box tar execution; generated script text is asserted and remote rc classes are simulated through the services fake; ETIMEDOUT/EINTR transport semantics are exercised at the ssh module level and observed through fake return codes in launch/startstop
<!-- RECORD-COMPLETE -->
