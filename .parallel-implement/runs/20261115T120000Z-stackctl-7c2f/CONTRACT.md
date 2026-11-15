# Contract — 20261115T120000Z-stackctl-7c2f

Frozen shared interfaces for the stackctl implementation. Authoritative behavior spec:
/var/lib/opencode/dev/designs/stackctl.md (rev 8) — every lane reads it. This contract
freezes code-level interfaces so lanes can build independently. Lanes never edit this
file; propose changes via escalation to inbox/orchestrator/ only.

## Repo layout and build

- Language: C (gnu11), static musl via hermetic zig-cc toolchain; Bazel bzlmod only.
- One directory per module under core/: config, crypto, ini, state, ssh, knownhosts,
  aws, cfn, ec2, s3, ssm, ddns, dns; CLI under core/cli/ (cli.h + common/ + one
  directory per verb group + dispatch/); entrypoint core/main.c.
- Each module directory contains its own BUILD.bazel defining a cc_library named after
  the module (e.g. //core/config:config) plus colocated cc_test targets. Lanes write
  BUILD files only inside their own globs; the root BUILD.bazel and MODULE.bazel are
  owned by w1-vendor (wave 1) and finalized by w5-build (wave 5).
- No module except core/aws (curl), core/ddns (curl, own seam), core/dns (c-ares) and
  the status IP-echo call site may reference network symbols.

## Shared conventions (all lanes)

- Prefix all public symbols with the module name: `config_`, `crypto_`, `sigv4_`,
  `aws_`, `cfn_`, `ec2_`, `s3_`, `ssm_`, `ddns_`, `dns_`, `ini_`, `state_`, `sshc_`,
  `kh_`, `cli_`.
- Error model: every function returns 0 on success, non-zero errno-style error code
  otherwise; out-params for results. No exceptions, no exit() inside library modules
  except CLI verb layers.
- Allocation: caller-allocated buffers where feasible; heap returns via out-param +
  explicit `_free()` destructor when needed. No global mutable state except state
  module's locked store.
- JSON: yyjson only (vendored); no other JSON.
- Logging/diagnostics: stderr only; stdout reserved for CLI output (--json on stdout).
- Exit codes (frozen, spec §4): 0 success; 1 usage/config; 2 AWS API error after
  retries; 3 verification failure; 4 launch failed + instance terminated; 5
  teardown/cleanup incomplete; 6 freshness gate; 7 SSH transport failure.

## Frozen module interfaces (header files, exact paths)

### core/config/config.h (w1-config)
- `typedef struct stackctl_config stackctl_config;` — opaque; typed getters:
  `config_get(cfg, "KEY") -> const char*` (NULL if unset), `config_region(cfg)`,
  `config_project(cfg)`, `config_arch_list(cfg)`.
- `int config_load(const char *dir, int region_explicit, const char *region_flag,
  stackctl_config **out);` — resolves .env vs .env.<region>, fail-closed validation
  (unknown key = error), region consistency checks, PROJECT regex `^[a-z][a-z0-9]+$`
  with per-region length bound (bucket-name 63-char rule).
- `int config_repo_root(const char *config_dir, char **root_out);` — real-path
  walk-up to MODULE.bazel; `const char *config_build_working_directory(void);` —
  getenv("BUILD_WORKING_DIRECTORY") or NULL.

### core/crypto/crypto.h (w1-crypto)
- `void crypto_sha256(const void *data, size_t len, uint8_t out[32]);`
  streaming: `crypto_sha256_ctx`, init/update/final.
- `void crypto_hmac_sha256(const uint8_t *key, size_t keylen, const void *data,
  size_t len, uint8_t out[32]);`
- SigV4: `int sigv4_sign(const char *service, const char *region,
  const char *host, const char *method, const char *canonical_uri,
  const char *canonical_query, const char *payload_hash_or_NULL_for_unsigned,
  const char *amz_date, const char *amz_date_stamp,
  const char *access_key, const char *secret_key, const char *session_token_or_null,
  char out_authorization[512]);`
- Unit tests against NIST SHA-256/HMAC vectors and the published AWS SigV4
  GET-vanilla example are mandatory.

### core/ini/ini.h, core/state/state.h, core/ssh/ssh.h, core/knownhosts/knownhosts.h (w1-local)
- ini: `int ini_upsert_section(const char *path, const char *section,
  const char *key, const char *secret, char **backup_path_out);` — timestamped
  backup, unrelated sections preserved.
- state: `int state_open(const char *project, const char *region,
  state_store **out);` — XDG dir `$XDG_STATE_HOME/stackctl/<project>.<region>/`
  (0700); `state_lock(project, region, timeout_sec)` exclusive flock at
  `stackctl/<project>.<region>.lock`; binding map
  `kh_binding {instance_id, host_key, fqdn, ip}` ops:
  `state_binding_get/put/replace/forget`; `state_launch_record_append`;
  `state_release_history_append(tag)`; `state_operations_log_append(verb, args,
  outcome)` (0600 append-only, never secrets).
- ssh: `int sshc_build_argv(...)` — one builder producing the -o option set of spec
  §4 (BatchMode, IdentitiesOnly, UpdateHostKeys=no, ControlMaster=no,
  ControlPath=none, UserKnownHostsFile, StrictHostKeyChecking, HostKeyAlias,
  ServerAlive*, Port, User) for both ssh and scp; `int sshc_exec(argv, timeout,
  sentinel_spec_or_null, int *remote_rc)` implementing the `STACKCTL_RC=<n>`
  sentinel + exit-255 reconnect-once rule; child process-group SIGTERM(5s)→SIGKILL.
- knownhosts: `int kh_pin(const char *store_path, const char *instance_id,
  const char *scanned_key_line);` write-only dedicated store, entries keyed by
  HostKeyAlias=instance-id; `kh_bound(store, instance_id) -> bool`.

### core/aws/aws.h (w2-awsclient)
- `typedef struct aws_ctx aws_ctx;`
- `int aws_init(aws_ctx **out, const char *profile_name);` — reads ONLY the named
  profile from ~/.aws/credentials via core/ini; strips all AWS_* env vars except the
  test endpoint override `STACKCTL_ENDPOINT_URL`.
- `int aws_request(aws_ctx*, const aws_req *req, aws_resp *resp);` — single HTTP
  seam: connection reuse, retry exp-backoff+jitter max 6 on 5xx/429/transient,
  timeout policy, SigV4 via core/crypto, path-style S3 addressing,
  UNSIGNED-PAYLOAD for S3 PUT/GET; resp carries status, headers, body (yyjson
  parsed on demand).
- Waiters: `aws_wait(aws_ctx*, waiter_fn, void *ud, int attempts, int interval_sec,
  int *timed_out)` — generic bounded polling.
- Clock-skew 403 detection: report local vs server Date delta, never auto-adjust.

### core/ddns/ddns.h and core/dns/dns.h (w2-ddns)
- dns: `int dns_a_record(const char *domain, const char *host, char ip[64],
  bool *parked);` — c-ares, ARES_FLAG_NORECURSE + authoritative NS discovery;
  parked = 0.0.0.0 or 127.0.0.1; `int dns_record_exists(domain, host, bool *exists);`
- ddns: `int ddns_update(const char *host, const char *domain,
  const char *password, const char *ip, bool *updated);` — libcurl GET on
  https://dynamicdns.park-your-domain.com/update, host/domain case-sensitive,
  success parsed from XML body `<ErrCount>0</ErrCount>`, NUL-stripped; password
  never argv, never logged. `int ddns_ip_echo(const char *url, char ip[64]);` —
  plain-HTTPS helper reused by status.

### deploy/ (w2-templates)
- `deploy/stackctl-operator.yaml`, `deploy/stackctl-infra.yaml` — canonical CFN
  templates per spec §6.1/§6.2; `deploy/template_check.py`-free: implement the
  structural checker as `deploy/check/` C test harness (or sh_test driver) with no
  Python dependency, validating the §6.3 contract (required present-and-referenced
  parameters, required outputs, stack name = ProjectName, no Exports, bucket
  DeletionPolicy RetainExceptOnCreate + UpdateReplacePolicy Retain, least-privilege
  structural assertions).

### core/cfn/cfn.h, core/ec2/ec2.h, core/s3/s3.h, core/ssm/ssm.h (w3-*)
Request-builders + response-parsers over core/aws only. Required surface:
- cfn: describe_stacks, create_change_set, describe_change_set, execute_change_set,
  delete_change_set, get_template_summary, delete_stack, stack-status enum mapping
  the spec §4 provision/deploy state table, waiter for stack ops.
- ec2: run_instances (spot/on-demand, ClientToken, tag-gated TagSpecifications
  instance-only: Project/Name/stackctl:launch-nonce), describe_instances (filters,
  public-ip waiter), terminate_instances + terminated waiter, get_console_output,
  describe_images.
- s3: put_object (sidecar-then-object order), get_object, head_object, delete_object,
  list_objects_v2 (prefix), read-back sha verify helpers over core/crypto.
- ssm: get_parameter (SecureString /<project>/ddns/password), get_parameter for AMI
  floats (baked/ssm policies).

### core/cli/cli.h and core/cli/common/ (w3-cliapi)
- `typedef struct cli_ctx cli_ctx;` — carries parsed globals (--region, --project,
  --json, --yes, --dry-run, --lock-timeout), loaded config, state store handle,
  exit-code classification helpers `cli_fail(ctx, code, fmt, ...)`.
- Verb registration (frozen; dispatch in wave 5 calls these exact names):
  `int cli_cmd_provision(cli_ctx*); int cli_cmd_deploy(cli_ctx*);`
  `int cli_cmd_refresh_ami(cli_ctx*); int cli_cmd_launch(cli_ctx*);`
  `int cli_cmd_terminate(cli_ctx*); int cli_cmd_status(cli_ctx*);`
  `int cli_cmd_start(cli_ctx*); int cli_cmd_stop(cli_ctx*);`
- `cli_ctx` construction: `int cli_ctx_init(int argc, char **argv, cli_ctx **out);`
  including global-flag parsing, config load, lock acquisition policy per verb
  (status lockless), signal handlers (first signal → failure path, second → immediate
  death), TTY detection for the `apply? [y/N]` rule.

### core/cli/<verb>/** (wave 4) — implementation against cli.h + service modules,
per spec §4 verb semantics (provision/deploy/refresh-ami in w4-verbs-stack;
launch/terminate/status/start+stop in w4-verbs-instance). Each verb directory exposes
`<verb>.h` with only `cli_cmd_<verb>` and implements spec behavior including
preflights, exit-code mapping, audit-log appends.

### core/main.c and core/cli/dispatch/** (w5-main)
- main(): parse globals, select verb by name, call cli_cmd_<verb>, map to exit code;
  `--version` prints VERSION file content + spec rev.

### tests/** (w5-tests)
- Integration: local C mock HTTP server (ddns_test_server.c pattern) exercising the
  http seam with fixture responses for every AWS call; endpoint override wired
  through the binary. Contract tests: exit-code table, env-contract stability
  (STACKCTL_DDNS_PASSWORD_FILE present iff DDNS_ONBOX=true), known-hosts binding
  semantics (new instance-id replaces; same id + changed key = hard error),
  remote-status sentinel, launch-replace/terminate semantics, network-seam link
  test (only aws/ddns/dns + status echo reference socket symbols).

## Per-lane acceptance criteria

- Every lane: compiles conceptually against this contract (headers exactly as
  frozen); colocated cc_test targets for its unit-testable surface; done record
  lists produced paths; no writes outside declared globs.
- w1-vendor: MODULE.bazel with sha256-pinned http_archives (curl 8.23.0, mbedTLS
  4.1.1 release tarball, yyjson 0.13.0, c-ares pinned) + hermetic_cc_toolchain
  4.3.0 / rules_cc 0.2.28; third_party/ overlay BUILD files per spec §11 vendoring
  rules (three cc_library for mbedTLS with correct link order, ~11 include roots,
  two config files, mbedtls-framework excluded); minimal root BUILD.bazel.
- w1-config: config validation table tests incl. PROJECT regex, per-region length
  bound, region consistency, repo-root walk-up under BUILD_WORKING_DIRECTORY
  set/unset.
- w1-crypto: NIST + AWS SigV4 vector tests green.
- w2-awsclient: retry/timeout/endpoint-override unit tests; aws_request used by NO
  module other than cfn/ec2/s3/ssm (+ verbs via those).
- w2-templates: checker validates both canonical templates pass §6.3; least-privilege
  structural assertions pass.
- w3-cliapi: cli_ctx_init parses globals; registration names exactly as frozen.
- wave 4 verbs: spec §4 semantics per verb incl. preflight order, exit codes,
  change-set confirmation + DeleteChangeSet-on-decline, DDNS snapshot/restore rules,
  launch replace semantics, terminate park semantics.
- w5-build: `bazel build //...` target graph complete (command + exit code evidence).
- w5-tests: link-time network-seam test present; mock-server integration harness
  present.
- w5-docs: README.md documents build, verbs, exit codes, on-box contract;
  AGENTS.md remains without a build-policy block unless it documents commands in
  prose.

## Amendment 1 — C23 language standard (operator-authorized, 2026-11-15)

All stackctl-authored C code (core/**, tests/**, and hand-written third_party overlay
code such as config headers and BUILD files) MUST use the C23 standard: compile with
`-std=gnu23` (or `-std=c23` where no extensions are used). This supersedes the gnu11
convention in "Repo layout and build". Vendored upstream sources (curl, mbedTLS,
yyjson, c-ares tarball contents) are NOT modified — their builds keep whatever flags
they need; only the `-std` applied to stackctl-authored translation units changes.
Existing wave-1 artifacts were rewritten to C23 by orchestrator delegation on
2026-11-15; all later lanes compile and test under C23.

## Amendment 2 — TDD discipline: RED -> GREEN -> REFACTOR (operator-authorized, 2026-11-15)

Every piece of the stackctl implementation is built test-driven. Each unit of work in
a lane's journal must show the three phases with evidence:
- RED: the test for the next behavior is written FIRST and observed failing (quote the
  failing assertion/output and the command + exit code in the journal step).
- GREEN: the minimal implementation that makes the test pass (command + exit code).
- REFACTOR: cleanup of the new code (and only nearby code) with the full suite still
  green (command + exit code). No refactor step may change behavior.
Colocated cc_test targets are the vehicle; a lane's done record must assert that every
public function of its modules is covered by at least one test that can be shown to
fail when the function is broken. Wave-1 artifacts written before this amendment keep
their existing suites; a gap-fill pass (2026-11-15) added missing tests and verified
via mutation checks that the suites detect seeded defects.

## Amendment 3 — Lint policy: all languages, gates every verification (operator-authorized, 2026-11-15)

Every language present in the repo is linted with reasonable defaults, and lint MUST
pass at every verification step: each lane's done record includes a lint line
(`lint: <command> -> exit 0`) for its globs; per-wave independent review treats a lint
failure or missing lint evidence as a defect; the terminal verification stage runs the
full AGENTS.md `[verify]` table including `lint`. Languages and tools (see Amendment 4
for hermetic sourcing): C -> cppcheck (plus -Wall -Wextra -Werror compiler gate);
Starlark (BUILD.bazel/MODULE.bazel/*.bzl) -> buildifier (lint mode); YAML ->
yamllint (or the C template checker for CFN templates); shell -> shellcheck;
Markdown -> the configured markdown checker. Config files with reasonable defaults
live at repo root (.clang-tidy or cppcheck config, .yamllint, buildifier table in
.bazelrc or BUILD config, markdownlint config) and are orchestrator-owned after this
amendment: lanes never edit them; violations are fixed in the lane's own sources.

## Amendment 4 — Hermetic tooling only (operator-authorized, 2026-11-15)

No verification or lint step relies on host-installed tools. Every tool needed
(linters, test runners, compilers) is pulled into the hermetic Bazel environment as a
pinned http_archive / bazel_dep / pinned toolchain and invoked through Bazel
(`bazel run //tools/...` or `bazel test`). Python-based tools, if any, use a pinned
rules_python toolchain — never host python. Evidence commands in lane records must be
bazel-invoked hermetic commands (system `cc` may still be used as extra developer
evidence but never as the required gate). The AGENTS.md build-policy `[verify]` table
maps each key to a bazel-wrapped hermetic command.

## Amendment 5 — Signed extra request headers (X-Amz-Target seam) (orchestrator-authorized, 2026-11-15)

<!-- ref: w3-ssm-20261115T034643Z-ssm-x-amz-target-seam -->

Append-only extension requested by `w3-ssm-20261115T034643Z-ssm-x-amz-target-seam`. AWS JSON-1.1
services (notably SSM) require a signed `X-Amz-Target` header plus
`Content-Type: application/x-amz-json-1.1`; the frozen `aws_req`/`sigv4_sign` surfaces of
waves 1/2 could not express or sign an arbitrary `x-amz-*` header. This supersedes nothing:
all previously frozen behavior and signatures remain unchanged.

### `struct aws_req` (core/aws/aws.h) — additive fields

```c
const char *const *extra_headers;   /* NULL-terminated not required; array of count lines */
size_t extra_header_count;
```

- Each entry is one outbound header line `"Name: value"`, caller-owned and valid for the
  duration of the call. The library copies nothing beyond the call.
- Entries whose name begins with `x-amz-` (ASCII case-insensitive) MUST be included in the
  SigV4 canonical headers and the `SignedHeaders` list.
- Other entries are sent on the wire but not signed, except `content-type` (ASCII
  case-insensitive), which stackctl signs as a canonical header when the signer extension
  includes it.
- Lines without a `':'`, or with an empty name, or containing CR/LF in the name or value,
  are invalid and cause `aws_request`/`aws_http_execute` to return `EINVAL`.
- `content_type` continues to be handled exactly as before (emitted as `Content-Type` and
  not signed).

### `sigv4_sign_with_headers` (core/crypto/crypto.h) — additive function

The existing `sigv4_sign` signature and behavior are unchanged. Add:

```c
int sigv4_sign_with_headers(const char *service, const char *region,
                            const char *host, const char *method,
                            const char *canonical_uri, const char *canonical_query,
                            const char *payload_hash_or_NULL_for_unsigned,
                            const char *amz_date, const char *amz_date_stamp,
                            const char *access_key, const char *secret_key,
                            const char *session_token_or_null,
                            const char *const *extra_headers, size_t extra_header_count,
                            char out_authorization[CRYPTO_SIGV4_AUTH_LEN]);
```

Semantics:

- Canonical headers are the fixed set `host`, `x-amz-date` (and `x-amz-security-token`
  when a session token is supplied) plus **all** provided extra headers. Header names are
  lowercased and trimmed; values have leading/trailing space trimmed and internal runs of
  spaces collapsed to one; entries are sorted by (lowercased) name.
- `SignedHeaders` lists exactly those canonical header names, in the same sorted order.
- The caller must send every signed header on the outbound request.
- `extra_headers == NULL && extra_header_count == 0` is valid. `extra_headers == NULL`
  with a non-zero count, an empty name, a duplicate name (including a duplicate of a fixed
  header), a missing `':'`, or CR/LF in a name or value yields `-EINVAL`. Oversized input
  that would overflow an internal buffer yields `-ERANGE`. Return conventions match the
  existing crypto style (negative errno).

### `aws_request` (core/aws/request.c)

`build_signed_headers()` appends every `extra_headers` line to the outgoing header array and
passes the `x-amz-*` (and `content-type`) entries to `sigv4_sign_with_headers`, so the
signature covers every `x-amz-*` extra. Invalid extra lines are rejected with `EINVAL`.
With `extra_header_count == 0` the emitted headers and signature are byte-identical to the
pre-amendment behavior.

### Acceptance

- SSM can set
  `extra_headers = {"X-Amz-Target: AmazonSSM.GetParameter", "Content-Type: application/x-amz-json-1.1"}`
  (with `unsigned_payload = 0`) and the SigV4 signature covers `x-amz-target`.
- `core/crypto` tests a published-style vector for an extra signed header, `EINVAL` cases,
  and a `SignedHeaders` sort/coverage check. `core/aws` tests assert the outbound extra
  lines,   `SignedHeaders` coverage of `x-amz-target`, and unchanged behavior when
  `extra_header_count == 0`.

## Amendment 6 — IAM/STS service module (orchestrator extension)

<!-- ref: wave-4 review + operator authorization -->

This append-only amendment freezes the interface of a new service module,
`core/iam/**`, added by the operator as an orchestrator-directed extension
outside the original frozen lane map (`WAVES.md` is unchanged; see
`state/waves/4.retry-1.md` and `state/waves/4.orchestrator-extension-iam.md`).
Wave-4 verbs consume it instead of calling `aws_request`/STS directly; the
contract rule that only cfn/ec2/s3/ssm may reference the AWS request seam is
extended to include iam. This supersedes no previously frozen signature.

```c
/* core/iam/iam.h */
typedef struct iam_key {
    char *user_name;
    char *access_key_id;
    char *secret_access_key;  /* NULL except for iam_create_access_key results */
    char *status;             /* "Active"/"Inactive" */
    char *create_date;        /* ISO-8601 as returned */
} iam_key;

int iam_get_caller_identity(aws_ctx *ctx, char **out_account, char **out_arn, char **out_user_id);
int iam_list_access_keys(aws_ctx *ctx, const char *user_name_or_null, iam_key **out, size_t *out_count);
int iam_create_access_key(aws_ctx *ctx, const char *user_name_or_null, iam_key *out);
int iam_delete_access_key(aws_ctx *ctx, const char *user_name_or_null, const char *access_key_id);
void iam_key_free(iam_key *key);
void iam_keys_free(iam_key *keys, size_t count);
```

Semantics:

- STS/IAM Query protocol over the frozen `aws_request` seam; service names
  `"sts"` and `"iam"`.
- `user_name_or_null` NULL means the caller's own user.
- Errors return positive errno-style codes with AWS error text on stderr (no
  secrets).
- `iam_create_access_key` fills the secret only in its result.
- All out-params are untouched on failure.
- Every heap field is freed by the free functions.
- Callers zero-initialise `iam_key` before `iam_create_access_key`.

<!-- ref: wave-4 review + operator authorization -->
