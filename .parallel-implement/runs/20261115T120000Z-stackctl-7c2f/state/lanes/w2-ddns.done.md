---
lane: w2-ddns
wave: 2
status: complete
assumptions: split core/dns into :dns_core (dns.c, no network), :dns_wire (c-ares query/reply helpers, synthetic-reply testable), and :dns (c-ares transport), mirroring the :ddns_core/:ddns seam so the public dns_a_record/dns_record_exists wrappers are testable without sockets; the retasked attempt-2 record supersedes the earlier attempt-1 record (this file was atomically replaced via temp+fsync+rename); `bazel test //...` was not green at finish solely because //deploy/check:template_check_test (w2-templates globs) is mid-edit and its testdata files are temporarily missing
confidence: medium
timestamp: 2026-11-15T03:13:15Z
---
## Evidence
- inbox: empty (only the pre-existing mbedtls-config-link reply was present; treated resolved and not rewritten)
- build: `bazel build //...` -> exit 0
- test: `bazel test //core/dns:dns_test --test_output=errors` -> exit 0 (PASSED). RED before the fix was exit 3 with exactly: "wire NS count" (h_name injected -> 3 instead of 2), "wire NS excludes queried name", "empty answer rejected".
- test-adjacent: `bazel test //...` -> exit 1/3 at finish because //deploy/check:template_check_test fails to build (missing deploy/check/testdata/bad_infra_bucket.yaml, bad_operator_action_intrinsic.yaml, bad_operator_resource_intrinsic.yaml). Those paths are outside this lane's globs and are owned by the concurrent w2-templates retry lane; 13/14 tests pass, including //core/dns:dns_test and //core/ddns:ddns_test.
- lint: `bazel run //tools/lint:lint` -> exit 0 (cppcheck, buildifier, shellcheck, yaml_check, markdown_check clean)
- fix 1 (major): core/dns/dns_cares.c no longer contains ares_getaddrinfo/resolve_ipv4() anywhere; NS-name and authoritative record lookups both use ares_query(channel, name, ns_c_in, ns_t_a, ...) plus ares_parse_a_reply (via dns_wire_parse_a_reply). The authoritative channel keeps ARES_FLAG_NORECURSE with per-server ARES_OPT_SERVERS; no hosts-file or RFC-6724 path remains.
- fix 2 (major): dns_wire_parse_ns_reply collects only host->h_aliases from ares_parse_ns_reply; host->h_name (the queried name) is never added, so servers[0] is a real authoritative NS. Covered by a synthetic NS-reply test that asserts the queried name is absent and the two NS targets are first/second.
- fix 3 (minor): dns_a_record_with rejects found==true with an empty answer (returns EIO and clears ip) instead of success with ip="".
- fix 4 (minor): dns_test supplies dns_cares_ops() (the public seam) and exercises dns_a_record()/dns_record_exists() success paths end-to-end through the injected fake (no sockets).
- produced: core/dns/dns.c; core/dns/dns_cares.c; core/dns/dns_wire.c; core/dns/dns_wire.h; core/dns/dns_internal.h (unchanged API); core/dns/dns_test.c; core/dns/BUILD.bazel; journal logs/w2-ddns.md
- disconfirming: real c-ares/UDP behaviour against live authoritative servers is compile-verified only (hermetic tests use synthetic wire replies, per Amendment 4); the ares_parse_ns_reply path assumes NS RRs in the answer section (same assumption as the prior implementation); `bazel test //...` must be re-run green by the orchestrator after w2-templates completes.
<!-- RECORD-COMPLETE -->
