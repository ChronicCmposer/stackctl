---
lane: w1-config
wave: 1
status: complete
assumptions: Req=✔ keys must be present (SSH_PORT/SETUP_ENTRYPOINT required despite documented defaults); AMI_ID_* allowed only when AMI_POLICY=pinned; AMI_SSM_* allowed under pinned/baked but required under ssm; DDNS_HOST and DDNS_DOMAIN must travel as a pair; duplicate .env keys are hard errors; config_arch_list returns a NULL-terminated const char *const *; config_load resolves relative --project via BUILD_WORKING_DIRECTORY else cwd; cc_test links -static because the host lacks the musl loader
confidence: high
timestamp: 2026-11-15T01:24:25Z
---
## Evidence
- inbox: empty
- build: bazel test //core/config:config_test -> exit 0 (PASSED); cc -std=gnu11 -Wall -Wextra -Werror -pedantic config_test.c config.c envfile.c -> exit 0; /tmp/config_test -> exit 0; clang pedantic syntax -> exit 0; ASan/UBSan run -> exit 0
- produced: core/config/config.h; core/config/envfile.h; core/config/envfile.c; core/config/config.c; core/config/config_test.c; core/config/BUILD.bazel
- disconfirming: not exercised against a real w3-cliapi caller (interface frozen only by header); did not validate SSH_IDENTITY readability or AWS-side prerequisites (left to verb preflights); no Bazel build-policy block exists so the Bazel command above is the repo's own target, not a declared [verify] command
<!-- RECORD-COMPLETE -->
