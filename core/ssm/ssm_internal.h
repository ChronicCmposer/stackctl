/*
 * ssm_internal.h — unit-test seams for core/ssm.
 *
 * NOT part of the frozen public surface (ssm.h). Tests include this header to
 * inject a fake transport and to exercise the status/error mappings directly.
 *
 * The SSM API needs a signed `X-Amz-Target` header. `ssm_call` carries the
 * operation target explicitly, and `ssm_build_headers` produces the two
 * outbound header lines (`X-Amz-Target` and `Content-Type`) that the production
 * adapter places in `aws_req.extra_headers` for core/aws to sign (CONTRACT
 * Amendment 5). Tests inject a fake transport over the same seam.
 */

#ifndef STACKCTL_CORE_SSM_SSM_INTERNAL_H
#define STACKCTL_CORE_SSM_SSM_INTERNAL_H

#include <stddef.h>

#include "ssm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SSM JSON protocol constants (every operation). */
#define SSM_API_CONTENT_TYPE "application/x-amz-json-1.1"
#define SSM_TARGET_PREFIX "AmazonSSM."
#define SSM_REGION_MAX 64

/* Number of extra request headers every SSM JSON call carries. */
#define SSM_EXTRA_HEADER_COUNT 2

/* Capacity for one outbound `X-Amz-Target` header line. */
#define SSM_TARGET_HEADER_MAX 160

/*
 * One SSM operation: the core/aws request plus its `X-Amz-Target` value
 * (`AmazonSSM.<Operation>`). `target` is borrowed for the call.
 */
typedef struct ssm_call {
    aws_req req;
    const char *target;
} ssm_call;

/*
 * Transport seam: performs one SSM operation. The production adapter forwards
 * to aws_request(); tests replace it with a canned-response fake. Returning a
 * non-zero code aborts the operation with that code; an HTTP response
 * (whatever its status) returns 0 with `resp` populated.
 */
typedef int (*ssm_transport_fn)(aws_ctx *aws, const ssm_call *call,
                                aws_resp *resp, void *ud);

struct ssm_client {
    aws_ctx *aws; /* not owned */
    char region[SSM_REGION_MAX];
    ssm_transport_fn transport;
    void *transport_ud;
};

/*
 * Test/alternate constructor: same contract as ssm_client_init() plus an
 * injectable transport. `aws` may be NULL for fake-transport tests.
 */
int ssm_client_init_with_transport(ssm_client **out, aws_ctx *aws,
                                   const char *region,
                                   ssm_transport_fn transport, void *ud);

/*
 * Map an HTTP status plus optional SSM error code to an errno-style value.
 * 2xx -> 0, ParameterNotFound/InvocationDoesNotExist -> ENOENT,
 * AccessDeniedException -> EACCES, other non-2xx -> SSM_ERR_AWS_API.
 */
int ssm_status_to_errno(long status, const char *code);

/*
 * Build the `X-Amz-Target` value (`AmazonSSM.<operation>`) into `out`.
 * Returns 0, or EINVAL/EFBIG.
 */
int ssm_build_target(const char *operation, char *out, size_t out_size);

/*
 * Build the two outbound header lines every SSM JSON operation sends
 * (CONTRACT Amendment 5):
 *
 *   out[0] = "X-Amz-Target: AmazonSSM.<operation>"   (formatted into target_header)
 *   out[1] = "Content-Type: application/x-amz-json-1.1"
 *
 * `target_header` is caller storage that out[0] points into and that must
 * outlive the aws_request() call. Returns 0, or EINVAL/EFBIG.
 */
int ssm_build_headers(const char *operation, char *target_header,
                      size_t target_header_size,
                      const char *out[SSM_EXTRA_HEADER_COUNT]);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_SSM_SSM_INTERNAL_H */
