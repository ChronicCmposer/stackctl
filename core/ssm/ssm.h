/*
 * ssm.h — AWS Systems Manager Parameter Store client over core/aws
 * (spec §3/§4/§5, CONTRACT.md §core/ssm/ssm.h).
 *
 * Consumed behavior (spec §5, "GetParameter only"):
 *   - `ssm_get_parameter` reads the DDNS SecureString `/<project>/ddns/password`
 *     (launch + status preflight) and the public AMI parameters `AMI_SSM_*` /
 *     `/<project>/ami/baked/latest` (launch AMI resolution, refresh-ami).
 *   - start/stop use SSH, not Run Command, so this module owns no Run Command
 *     surface.
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
 * parameter maps to ENOENT and an authorization failure to EACCES.
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
#define SSM_ERROR_CODE_MAX 128

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

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_SSM_SSM_H */
