/*
 * cfn_internal.h — unit-test seam for core/cfn. Not part of the public API.
 *
 * The public client sends through aws_request(); tests substitute a fake
 * transport to assert exact request bodies and serve fixture responses without
 * any network or credentials.
 */

#ifndef STACKCTL_CORE_CFN_CFN_INTERNAL_H
#define STACKCTL_CORE_CFN_CFN_INTERNAL_H

#include "cfn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*cfn_transport_fn)(aws_ctx *ctx, const aws_req *req,
                                aws_resp *resp, void *ud);

/* Build a client whose requests are handled by `send(ctx, req, resp, ud)`.
 * `aws` may be NULL for a fake-only client (waiters still call `send`). */
int cfn_client_create_with_transport(cfn_client **out, aws_ctx *aws,
                                     cfn_transport_fn send, void *ud);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_CFN_CFN_INTERNAL_H */
