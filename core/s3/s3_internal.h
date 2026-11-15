/*
 * s3_internal.h — unit-test seams for core/s3. NOT part of the frozen public
 * surface (s3.h). Tests use this to drive every request with a fake transport
 * and to assert the HTTP-error mapping directly.
 */

#ifndef STACKCTL_CORE_S3_S3_INTERNAL_H
#define STACKCTL_CORE_S3_S3_INTERNAL_H

#include "s3.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Transport seam: one attempt. Matches core/aws's aws_request shape after
 * client construction; production wires aws_request(), tests wire a fake.
 */
typedef int (*s3_transport_fn)(void *ud, const aws_req *req, aws_resp *resp);

/* Test/alternate constructor: same contract as s3_client_init() plus transport. */
int s3_client_init_with_transport(s3_client **out, const char *region,
                                  s3_transport_fn transport, void *ud);

/*
 * Map an HTTP status plus optional S3 error code to an errno-style value.
 * 2xx -> 0. Exposed for table-driven unit tests of the error mapping.
 */
int s3_status_to_errno(long status, const char *code);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_S3_S3_INTERNAL_H */
