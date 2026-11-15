---
lane: w1-vendor
wave: 1
status: complete
assumptions: c-ares pinned to 1.34.9 (upstream latest, same pin as strimserver tools/ddns) because no c-ares 8.x release exists and spec §5.1 mandates the strimserver pin; curl built via a Bazel-native overlay reproducing autotools --with-mbedtls/HTTP_ONLY defines rather than running configure; mbedTLS minimal configs injected through a cross-repo @stackctl//third_party/mbedtls:config cc_library + -DMBEDTLS_CONFIG_FILE/-DTF_PSA_CRYPTO_CONFIG_FILE; mbedtls target srcs follow the upstream CMake source split (includes debug/mps_reader/mps_trace/net_sockets beyond the spec's shorthand); pqcp driver and mbedtls-framework subtree excluded from srcs; //... repo-wide build flags left to w5-build
confidence: high
timestamp: 2026-11-15T01:25:22Z
---
## Evidence
- inbox: empty
- build: bazel build --lockfile_mode=off //third_party/... @curl//:curl @mbedtls//:mbedtls @yyjson//:yyjson @cares//:cares -> exit 0
- build: bazel test --lockfile_mode=off //third_party/yyjson:yyjson_smoke_test //third_party/mbedtls:config_presence_test -> exit 0 (2/2 PASSED)
- build: bazel build --lockfile_mode=off --platforms=@zig_sdk//platform:linux_amd64 --extra_toolchains=@zig_sdk//toolchain:linux_amd64_musl @mbedtls//:mbedtls @curl//:curl @cares//:cares @yyjson//:yyjson -> exit 0 (amd64 cross, host arm64)
- build: bazel build --lockfile_mode=off //... -> exit 1 (peer lane core/crypto sigv4.c link relocations; not this lane's files)
- produced: MODULE.bazel; BUILD.bazel; third_party/curl/{BUILD.curl,BUILD.bazel}; third_party/mbedtls/{BUILD.mbedtls,BUILD.bazel,config_presence_test.c,configs/mbedtls_config.h,configs/crypto_config.h}; third_party/yyjson/{BUILD.yyjson,BUILD.bazel,yyjson_smoke_test.c}; third_party/cares/{BUILD.cares,BUILD.bazel,cares_linux_ares_config.patch}
- sha256: curl e3de77cfa6367083c776a26647fc9f633b538c06c3baa73d931a252ac8f72b49; mbedtls 3359a349e23db3d5536fcee032ae7b2ecbfc08972fab643089b5cbf2a375c98c; yyjson 34e0f62a2bc11ab20d601e8ca1cc2b2079503aa45119a19133d89d19b94a0fae; c-ares 9364b70a12eb59a06830fb488d9357f90100dff0d98b23ea3593a183d43e6f2f
- disconfirming: did not perform a live TLS handshake through curl/mbedTLS; did not consume the module from a separate bzlmod repo (strimserver/movienight); repo-wide `bazel build //...` currently fails in peer-owned core/crypto due to missing static/PIC build flags (.bazelrc not in this lane's globs), so end-to-end binary build is unverified at wave 1; arm64 evidence comes from the native host platform, amd64 from an explicit cross build.
<!-- RECORD-COMPLETE -->
