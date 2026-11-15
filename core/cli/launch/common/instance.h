/*
 * instance.h — shared substrate for the instance-lifecycle CLI verbs
 * (launch, terminate, status, start, stop). NOT a verb public header.
 *
 * The four verb packages all speak to the same universe: the project config,
 * the on-disk state store, and a set of AWS/DNS/SSH services. To keep each
 * verb testable without a network, credentials or a real PTY, the verbs are
 * written against `instance_runtime` (config snapshot + state store + I/O
 * policy) and `instance_services` (an injectable vtable over the frozen
 * module surfaces). Production wiring lives in instance_services.c; unit tests
 * fill the vtable with fakes and pass a synthetic config.
 *
 * This header is physically under core/cli/launch/common only because the
 * launch verb motivated it; all four verb packages depend on the same target
 * //core/cli/launch/common:instance_common.
 */

#ifndef STACKCTL_CLI_INSTANCE_H
#define STACKCTL_CLI_INSTANCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "cli.h"
#include "core/cfn/cfn.h"
#include "core/ddns/ddns.h"
#include "core/dns/dns.h"
#include "core/ec2/ec2.h"
#include "core/iam/iam.h"
#include "core/knownhosts/knownhosts.h"
#include "core/s3/s3.h"
#include "core/ssh/ssh.h"
#include "core/ssm/ssm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Config snapshot                                                           */
/* ------------------------------------------------------------------------- */

#define INST_PROJECT_MAX 128
#define INST_REGION_MAX 64
#define INST_ARCH_MAX 16
#define INST_AMI_ID_MAX 64
#define INST_SSM_PARAM_MAX 512
#define INST_TYPE_LIST_MAX 1024
#define INST_KEY_NAME_MAX 256
#define INST_PATH_MAX 1024
#define INST_USER_MAX 64
#define INST_CIDR_MAX 128
#define INST_UNIT_MAX 128
#define INST_ENTRYPOINT_MAX 256
#define INST_HOST_MAX 256
#define INST_DOMAIN_MAX 256
#define INST_URL_MAX 512
#define INST_BUCKETS_MAX 256
#define INST_TAG_MAX 128
#define INST_SHA_MAX 65
#define INST_FQDN_MAX 512
#define INST_FINGERPRINT_MAX 128

/*
 * The subset of the validated project config the instance verbs need, copied
 * into fixed buffers so tests can build one without touching the filesystem or
 * the opaque stackctl_config. Optional keys carry the documented defaults.
 */
typedef struct instance_config {
    char project[INST_PROJECT_MAX];
    char region[INST_REGION_MAX];
    char arch[INST_ARCH_MAX]; /* "amd64" | "arm64" | "both" */
    int spot_default;
    char ami_policy[INST_ARCH_MAX]; /* "pinned" | "ssm" | "baked" */
    char ami_id_amd64[INST_AMI_ID_MAX];
    char ami_id_arm64[INST_AMI_ID_MAX];
    char ami_ssm_amd64[INST_SSM_PARAM_MAX];
    char ami_ssm_arm64[INST_SSM_PARAM_MAX];
    char instance_types_amd64[INST_TYPE_LIST_MAX];
    char instance_types_arm64[INST_TYPE_LIST_MAX];
    int root_volume_size_gb;
    char root_volume_type[INST_ARCH_MAX];
    char key_name[INST_KEY_NAME_MAX];
    char ssh_identity[INST_PATH_MAX];
    char ssh_user[INST_USER_MAX];
    int ssh_port;
    char operator_cidr[INST_CIDR_MAX];
    char service_unit[INST_UNIT_MAX];
    char setup_entrypoint[INST_ENTRYPOINT_MAX];
    char ddns_host[INST_HOST_MAX];
    char ddns_domain[INST_DOMAIN_MAX];
    int ddns_onbox;
    char bucket_modules[INST_BUCKETS_MAX];
    char ip_echo_url[INST_URL_MAX];
    /* Repo root is needed by deploy only; the instance verbs do not use it. */
} instance_config;

/*
 * Snapshot the instance-verb-relevant keys from a loaded config. Returns 0 on
 * success or EINVAL when `ctx`/`out` is NULL.
 */
int instance_config_from_ctx(const cli_ctx *ctx, instance_config *out);

/* True when `key` is present and non-empty in `cfg`. */
bool instance_config_has(const instance_config *cfg, const char *key);

/* ------------------------------------------------------------------------- */
/* Services vtable (injectable)                                              */
/* ------------------------------------------------------------------------- */

/*
 * Opaque clients are borrowed for the lifetime of the services struct; tests
 * leave them NULL and the fake operations ignore them. Every function pointer
 * mirrors the frozen module signature (or a thin adapter) so a verb's
 * orchestration can be driven entirely by fakes.
 */
typedef struct instance_services {
    aws_ctx *aws;
    ec2_client *ec2;
    ssm_client *ssm;
    cfn_client *cfn;
    s3_client *s3;

    int (*ec2_run_instances)(ec2_client *, const ec2_run_spec *,
                             ec2_run_result *);
    int (*ec2_describe_instances)(ec2_client *, const ec2_filter *, size_t,
                                  ec2_instance_list *);
    int (*ec2_describe_images)(ec2_client *, const char *const *, size_t,
                               ec2_image_list *);
    int (*ec2_terminate_instances)(ec2_client *, const char *const *, size_t,
                                   ec2_terminate_result *);
    int (*ec2_wait_running)(ec2_client *, const char *, int, int, ec2_instance *,
                            int *);
    int (*ec2_wait_terminated)(ec2_client *, const char *const *, size_t, int,
                               int, int *);
    int (*ec2_get_console_output)(ec2_client *, const char *, char **);

    int (*cfn_describe_stacks)(cfn_client *, const char *, const char *,
                               cfn_stack_list *);
    int (*ssm_get_parameter)(ssm_client *, const char *, int, ssm_parameter *);
    int (*s3_head_object)(s3_client *, const char *, const char *,
                          unsigned long long *, char *);
    int (*s3_list_objects)(s3_client *, const char *, const char *,
                           s3_object_list *);
    int (*s3_get_object)(s3_client *, const char *, const char *, char **,
                         size_t *);

    int (*dns_a_record)(const char *, const char *, char *, bool *);
    int (*dns_record_exists)(const char *, const char *, bool *);
    int (*ddns_update)(const char *, const char *, const char *, const char *,
                       bool *);
    int (*ddns_ip_echo)(const char *, char *);

    /*
     * ssh-keyscan adapter: run `ssh-keyscan -t ed25519 -p <port> <ip>` and hand
     * back the first host-key line (heap-owned; free with free()), or NULL when
     * no key was produced. Returns 0, or an errno-style code on exec failure.
     */
    int (*keyscan)(const char *ip, int port, char **line_out);
    int (*ssh_exec)(char *const argv[], int timeout,
                    const sshc_sentinel_spec *, int *remote_rc);

    int (*kh_pin)(const char *, const char *, const char *);
    bool (*kh_bound)(const char *, const char *);
    int (*kh_forget)(const char *, const char *);

    /* STS identity guard (status). NULL in tests that do not exercise it. */
    int (*iam_get_caller_identity)(aws_ctx *, char **, char **, char **);
} instance_services;

/*
 * Open the production services (aws_init on the project profile, then the
 * ec2/ssm/cfn/s3 clients) and wire every function pointer to its module
 * implementation. Returns 0, or the first failing errno-style code; on failure
 * `svc` is left zeroed.
 */
int instance_services_open(instance_services *svc, const char *project,
                           const char *region);

/* Release clients opened by instance_services_open(). Safe on NULL/zeroed. */
void instance_services_close(instance_services *svc);

/*
 * Production ssh-keyscan adapter (fork/exec; no libssh). Exposed for the
 * services wiring and directly unit-testable with a fake PATH.
 */
int instance_keyscan_exec(const char *ip, int port, char **line_out);

/* ------------------------------------------------------------------------- */
/* Runtime (config + state + I/O policy)                                     */
/* ------------------------------------------------------------------------- */

typedef struct instance_runtime {
    instance_config cfg;
    state_store *state;
    instance_services svc;
    int json;
    int yes;
    int dry_run;
    /* Timing policy (tests set small values to avoid real sleeps). */
    int dns_attempts;   /* default 24 */
    int dns_interval;   /* seconds between attempts; default 5 */
    int wait_attempts;  /* EC2 waiter polls; default 60 */
    int wait_interval;  /* EC2 waiter seconds; default 5 */
    int ssh_attempts;   /* host-key polling attempts; default 60 */
    int ssh_interval;   /* seconds between host-key polls; default 5 */
    FILE *out;
    FILE *err;
    /*
     * Launch-record sink; defaults to state_launch_record_append with a NULL
     * state store treated as a no-op. Tests replace it to observe the record or
     * force an append failure without touching the filesystem.
     */
    int (*launch_record_append)(state_store *, const state_launch_record *);
    /* Confirmation hook; NULL => non-interactive unless `yes` is set. */
    int (*confirm)(void *ud, const char *prompt);
    void *confirm_ud;
} instance_runtime;

/*
 * Initialise a runtime from explicit parts (the test constructor). `state` and
 * `svc` are borrowed. `out`/`err` default to stdout/stderr when NULL.
 */
void instance_runtime_init(instance_runtime *rt, const instance_config *cfg,
                           state_store *state, const instance_services *svc,
                           int json, int yes, int dry_run);

/*
 * Initialise a runtime from a fully constructed CLI context plus services.
 * Installs the TTY-aware `cli_confirm` hook. Returns 0 or EINVAL.
 */
int instance_runtime_from_ctx(instance_runtime *rt, cli_ctx *ctx,
                              const instance_services *svc);

/* Ask for `apply? [y/N]`; returns a CLI_CONFIRM_* value. */
int instance_confirm(instance_runtime *rt, const char *prompt);

/* Output helpers honouring the runtime's streams. */
void instance_out(instance_runtime *rt, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void instance_err(instance_runtime *rt, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void instance_warn(instance_runtime *rt, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Report a failure on stderr and return `code` (mirrors cli_fail). */
int instance_fail(instance_runtime *rt, int code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Append a redacted operations-log entry; failures are warnings, not fatal. */
void instance_audit(instance_runtime *rt, const char *verb, const char *args,
                    const char *outcome);

/* ------------------------------------------------------------------------- */
/* DDNS orchestration helpers (operator-side, always)                        */
/* ------------------------------------------------------------------------- */

/* True when DDNS host+domain are configured for this project. */
bool instance_ddns_configured(const instance_runtime *rt);

/*
 * Read the current authoritative-NS A record into `ip`. Returns 0, ENOENT when
 * the record is absent, or a propagated error. `parked` is optional.
 */
int instance_dns_snapshot(instance_runtime *rt, char *ip, size_t cap,
                          bool *parked);

/* Apply one DDNS A-record update (never logs the password). */
int instance_ddns_set(instance_runtime *rt, const char *password,
                      const char *ip, bool *updated);

/*
 * Verify (bounded, authoritative-NS) that the A record reads `expected_ip`.
 * Sleeps `interval_sec` only between failed attempts. Returns 0 on match,
 * ETIMEDOUT when attempts exhaust, or a propagated error.
 */
int instance_dns_verify(instance_runtime *rt, const char *expected_ip,
                        int attempts, int interval_sec);

/*
 * Read the DDNS password SecureString `/<project>/ddns/password` (decrypted)
 * into `out`. Returns 0, ENOENT when absent, or a propagated error.
 */
int instance_ddns_password(instance_runtime *rt, char *out, size_t cap);

/* ------------------------------------------------------------------------- */
/* Pure helpers                                                              */
/* ------------------------------------------------------------------------- */

/* Base64 (standard alphabet) encode/decode. Return 0 or an errno-style code. */
int instance_base64_encode(const unsigned char *data, size_t len, char *out,
                           size_t out_size);
int instance_base64_decode(const char *text, unsigned char *out, size_t out_size,
                           size_t *out_len);

/*
 * Compute the OpenSSH SHA256 fingerprint (`SHA256:<base64-no-padding>`) of the
 * key blob in one ssh-keyscan line (`<host> <type> <base64> [comment]` or a
 * bare `<type> <base64>`). Returns 0, EINVAL on a malformed line, or ENAMETOOLONG.
 */
int instance_key_fingerprint(const char *key_line, char *out, size_t out_size);

/*
 * Extract every `SHA256:<base64>` token from a GetConsoleOutput block (cloud-
 * init's SSH HOST KEY FINGERPRINTS section). Returns the number of tokens
 * stored (up to `max`), a `count` out-param, or a negative errno-style code.
 */
int instance_console_fingerprints(const char *console, char fingerprints[][INST_FINGERPRINT_MAX],
                                  size_t max, size_t *count);

/*
 * Select the deployment member from a release manifest for `variant` (may be
 * NULL = unset) and `arch`. The manifest is a whitespace-separated
 * `<sha256> <member>` per line (sha256sum format). Returns 0 and fills
 * `member`/`sha256_hex`; EINVAL when the choice is ambiguous or `variant` is
 * missing, ENOENT when no member matches. Buffers are NUL-terminated.
 */
int instance_manifest_select(const char *manifest, const char *variant,
                             const char *arch, char *member, size_t member_size,
                             char *sha256_hex, size_t sha_size);

/*
 * Resolve the launch arch. `config_arch` is the validated ARCH value; `flag`
 * is --arch or NULL. Returns 0 with `out` set, EINVAL with `*why` naming the
 * problem (callers print it), or ENOENT.
 */
int instance_select_arch(const char *config_arch, const char *flag_arch,
                         char *out, size_t out_size, const char **why);

/*
 * Validate `--instance-type` against the comma allowlist for `arch`. When
 * `type` is NULL the first allowlisted entry is returned in `out`. Returns 0,
 * EINVAL (not allowlisted / empty list), or ENAMETOOLONG.
 */
int instance_resolve_type(const instance_config *cfg, const char *arch,
                          const char *type, char *out, size_t out_size);

/* True for the instance states a launch/terminate sweep considers live. */
bool instance_state_active(const char *state);
/* True for states terminate sweeps (includes shutting-down). */
bool instance_state_terminable(const char *state);

/* Parse a strictly positive decimal integer. Returns 0/EINVAL/ERANGE. */
int instance_parse_seconds(const char *text, int *out);

/* Build the FQDN `<host>.<domain>`; returns 0 or ENAMETOOLONG. */
int instance_fqdn(const char *host, const char *domain, char *out,
                  size_t out_size);

/* Lowercase hex SHA-256 of `project:nonce` (a RunInstances ClientToken). */
int instance_client_token(const char *project, const char *nonce, char out[65]);

/* Fill `out` with 32 lowercase hex chars from the kernel CSPRNG. */
int instance_nonce(char out[33]);

/*
 * Choose the DDNS restore target after a failed launch: the snapshot IP only
 * while it is still the public IP of a running instance in `list`, else the
 * park address `0.0.0.0`. Returns the chosen IP (never NULL).
 */
const char *instance_restore_ip(const char *snapshot_ip,
                                const ec2_instance_list *list);

/* Look up one instance by id in a list; NULL when absent. */
const ec2_instance *instance_find(const ec2_instance_list *list,
                                  const char *instance_id);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_INSTANCE_H */
