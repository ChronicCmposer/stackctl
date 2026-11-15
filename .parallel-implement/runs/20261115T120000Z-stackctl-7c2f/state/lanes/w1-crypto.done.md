---
lane: w1-crypto
wave: 1
status: complete
assumptions: get-vanilla vector tested with published service name `service` (true published signature) plus an IAM-scoped variant, because task text said service iam but the canonical published vector uses `service`; BUILD.bazel loads @rules_cc per contract
confidence: high
timestamp: 2026-11-15T01:19:14Z
---
## Evidence
- inbox: empty
- build: cc -std=gnu11 -Wall -Wextra -Werror -O2 -I core/crypto core/crypto/sha256.c core/crypto/hmac.c core/crypto/sigv4.c core/crypto/crypto_test.c -o /tmp/crypto_build/crypto_test -> exit 0
- build: /tmp/crypto_build/crypto_test -> exit 0 ("all crypto vectors passed")
- build: bazel test //core/crypto:crypto_test -> exit 1 (rules_cc repo unresolved; root MODULE.bazel empty, owned by w1-vendor — not a crypto defect)
- produced: core/crypto/crypto.h, core/crypto/sha256.c, core/crypto/hmac.c, core/crypto/sigv4.c, core/crypto/crypto_test.c, core/crypto/BUILD.bazel
- disconfirming: Bazel target not exercised because MODULE.bazel/BUILD.bazel are empty (w1-vendor scope); signatures for inputs other than the documented vectors (canonical_uri/query normalization, session-token header) were not independently cross-checked beyond the UNSIGNED-PAYLOAD and session-token code paths
<!-- RECORD-COMPLETE -->
