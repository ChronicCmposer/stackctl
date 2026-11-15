/*
 * wait.c — generic bounded polling for AWS waiters (instance running, IP
 * assigned, stack CREATE_COMPLETE). Each callback performs one poll.
 */

#include "aws_internal.h"

#include <errno.h>
#include <unistd.h>

int aws_wait(aws_ctx *ctx, aws_waiter_fn fn, void *ud, int attempts,
             int interval_sec, int *timed_out)
{
    if (fn == NULL || attempts < 1 || timed_out == NULL) {
        return EINVAL;
    }
    *timed_out = 0;
    for (int attempt = 0; attempt < attempts; attempt++) {
        int done = 0;
        int rc = fn(ctx, ud, &done);
        if (rc != 0) {
            return rc;
        }
        if (done) {
            return 0;
        }
        if (attempt + 1 < attempts && interval_sec > 0) {
            sleep((unsigned)interval_sec);
        }
    }
    *timed_out = 1;
    return 0;
}
