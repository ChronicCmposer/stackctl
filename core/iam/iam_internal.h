/*
 * iam_internal.h — unit-test seams and shared constants for core/iam.
 *
 * NOT part of the frozen public surface (iam.h). Tests include this header to
 * install a fake transport and to assert the exact request shape.
 */

#ifndef STACKCTL_CORE_IAM_IAM_INTERNAL_H
#define STACKCTL_CORE_IAM_IAM_INTERNAL_H

#include <stddef.h>

#include "iam.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IAM_STS_API_VERSION "2011-06-15"
#define IAM_API_VERSION "2010-05-08"
#define IAM_SIGNING_REGION "us-east-1"
#define IAM_ERROR_CODE_MAX 128
#define IAM_ERROR_MESSAGE_MAX 512

/* Upper bound on ListAccessKeys pages; IAM pages hold up to 100 keys and the
 * two-key limit is far below this, so the cap only guards against a malformed
 * or looping response. */
#define IAM_MAX_PAGES 64

/*
 * Transport seam: performs one signed request. The production adapter forwards
 * to aws_request(); tests replace it with a canned-response fake. Returning a
 * non-zero code aborts the operation with that code; an HTTP response
 * (whatever its status) returns 0 with `resp` populated and owned by the
 * caller (aws_resp_free()).
 */
typedef int (*iam_transport_fn)(aws_ctx *aws, const aws_req *req,
                                aws_resp *resp, void *ud);

/*
 * Test-only: install a fake transport used by every subsequent iam_* call, or
 * restore the production aws_request adapter with fn == NULL. Not thread-safe;
 * unit tests are single-threaded.
 */
void iam_test_set_transport(iam_transport_fn fn, void *ud);

/*
 * Build the form-encoded Query body for one IAM/STS operation. `user_name`
 * and `access_key_id` are optional (NULL = omit) and are percent-encoded.
 * Returns a heap-allocated NUL-terminated body (free(3)) and its length, or
 * NULL/0 with a positive errno-style code on failure.
 */
int iam_build_body(const char *action, const char *version,
                   const char *user_name, const char *access_key_id,
                   const char *marker, char **out_body, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_IAM_IAM_INTERNAL_H */
