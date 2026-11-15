/*
 * wait.c — generic bounded polling for AWS waiters (instance running, IP
 * assigned, stack CREATE_COMPLETE). Each callback performs one poll; an
 * optional abort hook, polled before every poll, lets a signal stop the wait
 * with EINTR so callers take their existing failure path.
 */

#include "aws_internal.h"

#include <errno.h>
#include <unistd.h>

static int wait_loop(aws_ctx *ctx, aws_waiter_fn fn, void *ud,
                     aws_abort_fn abort_fn, void *abort_ud, int attempts,
                     int interval_sec, int *timed_out)
{
    if (fn == NULL || attempts < 1 || timed_out == NULL) {
        return EINVAL;
    }
    *timed_out = 0;
    for (int attempt = 0; attempt < attempts; attempt++) {
        int done = 0;
        int rc;

        if (abort_fn != NULL && abort_fn(abort_ud) != 0) {
            return EINTR;
        }
        rc = fn(ctx, ud, &done);
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

int aws_wait(aws_ctx *ctx, aws_waiter_fn fn, void *ud, int attempts,
             int interval_sec, int *timed_out)
{
    aws_abort_fn abort_fn = ctx != NULL ? ctx->abort_fn : NULL;
    void *abort_ud = ctx != NULL ? ctx->abort_ud : NULL;

    return wait_loop(ctx, fn, ud, abort_fn, abort_ud, attempts, interval_sec,
                     timed_out);
}

int aws_wait_interruptible(aws_ctx *ctx, aws_waiter_fn fn, void *ud,
                           aws_abort_fn abort_fn, void *abort_ud, int attempts,
                           int interval_sec, int *timed_out)
{
    return wait_loop(ctx, fn, ud, abort_fn, abort_ud, attempts, interval_sec,
                     timed_out);
}

void aws_set_abort_hook(aws_ctx *ctx, aws_abort_fn abort_fn, void *abort_ud)
{
    if (ctx == NULL) {
        return;
    }
    ctx->abort_fn = abort_fn;
    ctx->abort_ud = abort_ud;
}
