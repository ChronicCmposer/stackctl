/*
 * ssm.h — AWS Systems Manager client (Parameter Store + Run Command) over
 * core/aws (spec §3/§4, CONTRACT.md §core/ssm/ssm.h).
 *
 * Consumed behavior (spec):
 *   - `ssm_get_parameter` reads the DDNS SecureString `/<project>/ddns/password`
 *     (launch + status preflight) and the public AMI parameters `AMI_SSM_*` /
 *     `/<project>/ami/baked/latest` (launch AMI resolution, refresh-ami).
 *   - `ssm_send_command` / `ssm_get_command_invocation` / `ssm_wait_command`
 *     expose Run Command for callers that choose it (the spec's start/stop
 *     verbs use SSH; these are a general surface, not a wave-4 dependency).
 *
 * The AWS SSM API is JSON-1.1: every request is `POST /` with a signed
 * `X-Amz-Target: AmazonSSM.<Operation>` header and `Content-Type:
 * application/x-amz-json-1.1` (CONTRACT Amendment 5). Request builders and
 * response parsers live here; the module never opens a socket and only calls
 * the core/aws seam.
 *
 * Error model (CONTRACT.md): functions return 0 on success and a non-zero
 * errno-style code otherwise; out-params are untouched on failure.
 * `SSM_ERR_AWS_API` (EREMOTEIO) marks an AWS error document; a missing
 * parameter/invocation maps to ENOENT and an authorization failure to EACCES.
 * Diagnostics go to stderr only.
 */

#ifndef STACKCTL_CORE_SSM_SSM_H
#define STACKCTL_CORE_SSM_SSM_H

#include <stddef.h>

#include "core/aws/aws.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Field capacities for parsed SSM resources. */
#define SSM_PARAM_NAME_MAX 2048
#define SSM_PARAM_TYPE_MAX 32
#define SSM_PARAM_DATATYPE_MAX 32
#define SSM_PARAM_ARN_MAX 512
#define SSM_PARAM_LAST_MODIFIED_MAX 64
#define SSM_COMMAND_ID_MAX 128
#define SSM_INSTANCE_ID_MAX 64
#define SSM_COMMAND_STATUS_MAX 32
#define SSM_COMMAND_STATUS_DETAILS_MAX 256
#define SSM_DOCUMENT_NAME_MAX 128
#define SSM_ERROR_CODE_MAX 128

/* Default Run Command document (spec: shell command execution). */
#define SSM_DOCUMENT_RUN_SHELL_SCRIPT "AWS-RunShellScript"

/*
 * Returned when AWS answered with an error document (HTTP non-2xx). Never an
 * errno value defined by the platform; the CLI maps it to its AWS-API exit code.
 */
#define SSM_ERR_AWS_API 121 /* EREMOTEIO */

/* Opaque client: an initialized aws_ctx plus the request region. */
typedef struct ssm_client ssm_client;

/* One parameter returned by GetParameter. Strings are heap-owned by the value;
 * release the whole struct with ssm_parameter_free(). */
typedef struct ssm_parameter {
    char *name;
    char *type;      /* "String" | "StringList" | "SecureString" */
    char *value;     /* decrypted when the read asked for decryption */
    char *arn;
    char *data_type; /* "text" | "aws:ec2:image" */
    long version;    /* 0 when AWS omitted it */
    char last_modified[SSM_PARAM_LAST_MODIFIED_MAX];
} ssm_parameter;

/* Lifecycle of an SSM command invocation (spec Run Command statuses). */
typedef enum ssm_command_status {
    SSM_COMMAND_UNKNOWN = 0,
    SSM_COMMAND_PENDING,
    SSM_COMMAND_IN_PROGRESS,
    SSM_COMMAND_DELAYED,
    SSM_COMMAND_SUCCESS,
    SSM_COMMAND_CANCELLED,
    SSM_COMMAND_TIMED_OUT,
    SSM_COMMAND_FAILED,
    SSM_COMMAND_CANCELLING
} ssm_command_status;

/* One GetCommandInvocation result. Output strings are heap-owned by the value;
 * release the whole struct with ssm_invocation_free(). */
typedef struct ssm_invocation {
    char command_id[SSM_COMMAND_ID_MAX];
    char instance_id[SSM_INSTANCE_ID_MAX];
    char status[SSM_COMMAND_STATUS_MAX];              /* raw AWS status string */
    ssm_command_status state;                         /* mapped enum */
    char status_details[SSM_COMMAND_STATUS_DETAILS_MAX];
    char *standard_output; /* NULL when AWS returned none */
    char *standard_error;  /* NULL when AWS returned none */
    long response_code;    /* -1 when AWS omitted it */
} ssm_invocation;

/* Inputs for SendCommand. Every pointer is borrowed for the call. */
typedef struct ssm_send_spec {
    const char *document_name;        /* NULL => AWS-RunShellScript */
    const char *const *commands;      /* required: shell command lines */
    size_t command_count;
    const char *const *instance_ids;  /* required: target instances */
    size_t instance_id_count;
    int timeout_seconds; /* <= 0 omits TimeoutSeconds */
    const char *comment; /* NULL omits Comment */
} ssm_send_spec;

/* Result of SendCommand. */
typedef struct ssm_send_result {
    char command_id[SSM_COMMAND_ID_MAX];
} ssm_send_result;

/*
 * Create a client bound to `aws` and `region`. `region` is copied. The client
 * borrows `aws` and never frees it. Returns 0, else EINVAL/ENOMEM.
 *
 * The production transport forwards every call to aws_request() with the SSM
 * JSON extra headers set (`X-Amz-Target` and `Content-Type`); tests inject a
 * fake transport over the same seam.
 */
int ssm_client_init(ssm_client **out, aws_ctx *aws, const char *region);

/* Release a client from ssm_client_init(). Safe on NULL. */
void ssm_client_free(ssm_client *client);

/*
 * GetParameter. `name` must be a fully-qualified parameter name beginning with
 * '/'. `with_decryption` non-zero sets WithDecryption=true (required for a
 * SecureString's plaintext). On success `out` is populated and must be released
 * with ssm_parameter_free(). ParameterNotFound maps to ENOENT.
 */
int ssm_get_parameter(ssm_client *client, const char *name, int with_decryption,
                      ssm_parameter *out);

/* Release a parameter populated by ssm_get_parameter(). Safe on NULL/zeroed. */
void ssm_parameter_free(ssm_parameter *parameter);

/*
 * SendCommand. Builds a JSON request with DocumentName, InstanceIds, the
 * `commands` parameter array, and optional TimeoutSeconds/Comment. The
 * returned CommandId identifies the invocation(s) for polling. Returns 0,
 * SSM_ERR_AWS_API, EINVAL, or another errno-style code.
 */
int ssm_send_command(ssm_client *client, const ssm_send_spec *spec,
                     ssm_send_result *out);

/*
 * GetCommandInvocation for one (command, instance) pair. Populates Status,
 * StatusDetails, StandardOutputContent, StandardErrorContent and ResponseCode.
 * InvocationDoesNotExist maps to ENOENT (the command has not reached the
 * instance yet). On success `out` must be released with ssm_invocation_free().
 */
int ssm_get_command_invocation(ssm_client *client, const char *command_id,
                               const char *instance_id, ssm_invocation *out);

/*
 * Poll GetCommandInvocation until the invocation reaches a terminal status
 * (Success/Cancelled/TimedOut/Failed) using `aws_wait`. A not-yet-created
 * invocation (InvocationDoesNotExist) is treated as "keep polling". `out`
 * receives the last observed invocation (terminal on success; the last
 * non-terminal state on timeout). Returns 0 with `*timed_out == 0` on
 * completion, 0 with `*timed_out == 1` on exhaustion, or a propagated error.
 */
int ssm_wait_command(ssm_client *client, const char *command_id,
                     const char *instance_id, int attempts, int interval_sec,
                     ssm_invocation *out, int *timed_out);

/* Release an invocation populated by ssm_get_command_invocation(). Safe on NULL. */
void ssm_invocation_free(ssm_invocation *invocation);

/* Map a raw AWS status string to the enum; NULL/unknown => SSM_COMMAND_UNKNOWN. */
ssm_command_status ssm_command_status_parse(const char *status);

/* Stable AWS status name for an enum value ("Unknown" for out-of-range). */
const char *ssm_command_status_name(ssm_command_status status);

/* Non-zero for Success/Cancelled/TimedOut/Failed, else 0. */
int ssm_command_status_terminal(ssm_command_status status);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_SSM_SSM_H */
