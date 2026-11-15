/*
 * aws.h — reusable AWS client layer (CONTRACT.md §core/aws/aws.h, spec §5).
 *
 * One HTTP seam for every AWS API call in stackctl: SigV4 signing via
 * core/crypto, connection reuse, bounded retries with exponential backoff and
 * jitter, path-style S3 addressing, `UNSIGNED-PAYLOAD` support, clock-skew
 * diagnosis and generic bounded waiters.
 *
 * Error model (CONTRACT.md): functions return 0 on success and a non-zero
 * errno-style code otherwise; results travel through out-params. Diagnostics go
 * to stderr only.
 *
 * Credentials: `aws_init` reads only the named profile from
 * `$HOME/.aws/credentials`. Every `AWS_*` environment variable is unset so an
 * ambient shell export can never select an identity; the only honored override
 * is the test endpoint `STACKCTL_ENDPOINT_URL`.
 */

#ifndef STACKCTL_CORE_AWS_AWS_H
#define STACKCTL_CORE_AWS_AWS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum total HTTP attempts per request (initial try + retries). */
#define AWS_MAX_ATTEMPTS 6

/* Capacity for an AWS error code reported by aws_error_code(). */
#define AWS_ERROR_CODE_LEN 128

/* Opaque client context: credentials, endpoint override, reusable connection. */
typedef struct aws_ctx aws_ctx;

/* One response header. Owned by aws_resp until aws_resp_free(). */
typedef struct aws_header {
    char *name;
    char *value;
} aws_header;

/*
 * One AWS API request.
 *
 *   service          SigV4 service name, e.g. "s3", "ec2", "cloudformation".
 *   region           SigV4 region, e.g. "us-east-1". Required.
 *   method           HTTP method, e.g. "GET", "POST", "PUT", "DELETE".
 *   path             Already percent-encoded canonical URI beginning with '/'.
 *                    For S3 this is path-style: "/<bucket>/<key>".
 *   query            Already percent-encoded canonical query string without the
 *                    leading '?', or NULL for none. Callers sort it (SigV4).
 *   body             Request body bytes, or NULL for none.
 *   body_len         Length of `body` in bytes.
 *   content_type     Optional Content-Type header value, or NULL.
 *   unsigned_payload Non-zero to sign with the literal `UNSIGNED-PAYLOAD`
 *                    (S3 PUT/GET); otherwise the SHA-256 of the body is signed.
 *   extra_headers    Optional array of `extra_header_count` outbound header
 *                    lines, each `"Name: value"`, caller-owned and valid for the
 *                    call. Lines whose name begins with `x-amz-` (case-
 *                    insensitive) are sent AND included in the SigV4 canonical
 *                    headers / SignedHeaders list; other lines are sent but not
 *                    signed, except `content-type`, which the signer signs when
 *                    supplied here. Invalid lines (no ':', empty name, CR/LF)
 *                    make aws_request() return EINVAL. NULL is valid only when
 *                    extra_header_count is 0. See CONTRACT Amendment 5.
 *   extra_header_count Number of entries in `extra_headers`.
 */
typedef struct aws_req {
    const char *service;
    const char *region;
    const char *method;
    const char *path;
    const char *query;
    const void *body;
    size_t body_len;
    const char *content_type;
    int unsigned_payload;
    const char *const *extra_headers;
    size_t extra_header_count;
} aws_req;

/*
 * One AWS API response.
 *
 * `status` is the HTTP status of the last attempt (0 when no response was
 * obtained). `headers`/`body` are heap-owned and released by aws_resp_free().
 * `json` is lazily populated by aws_resp_json(). Zero-initialise before use;
 * aws_request() resets it.
 */
typedef struct aws_resp {
    long status;
    aws_header *headers;
    size_t header_count;
    char *body;
    size_t body_len;
    struct yyjson_doc *json;
} aws_resp;

/*
 * Create a client for `profile_name`.
 *
 * Reads only `[<profile_name>]` from `$HOME/.aws/credentials` (keys
 * `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`). All
 * `AWS_*` environment variables are unset unconditionally, even when the
 * credential file is missing or unreadable; `STACKCTL_ENDPOINT_URL`, when set,
 * overrides the endpoint base URL for tests. `*out` receives a heap-allocated
 * context on success.
 *
 * Returns 0, else EINVAL (bad args), ENOENT (HOME/credentials/profile absent),
 * EFBIG (credentials file exceeds the 256 KiB cap), ENOMEM, or a read error.
 */
int aws_init(aws_ctx **out, const char *profile_name);

/* Release a context from aws_init(). Safe on NULL. */
void aws_free(aws_ctx *ctx);

/*
 * Perform one signed AWS API call with bounded retries.
 *
 * Retries with exponential backoff + jitter on 5xx, 429 and transient
 * transport errors, up to AWS_MAX_ATTEMPTS total attempts. Any HTTP response
 * received (including a final 4xx/5xx) yields return 0 with `resp->status`
 * populated so the caller can parse the AWS error envelope. Transport failure
 * after retries returns an errno-style code (ETIMEDOUT/ECONNRESET/EIO) with
 * `resp->status == 0`.
 *
 * On a clock-skew-class 403 the local vs server `Date` delta is reported to
 * stderr (diagnose only, never auto-adjust); see aws_clock_skew().
 */
int aws_request(aws_ctx *ctx, const aws_req *req, aws_resp *resp);

/* Release response headers, body and lazily parsed JSON. Safe on zeroed/NULL. */
void aws_resp_free(aws_resp *resp);

/* Case-insensitive header lookup; returns the value or NULL. */
const char *aws_resp_header(const aws_resp *resp, const char *name);

/*
 * Parse `resp->body` as JSON on first call and return the document (yyjson
 * type), or NULL when the body is absent or invalid. The document is owned by
 * `resp` and freed by aws_resp_free().
 */
struct yyjson_doc *aws_resp_json(aws_resp *resp);

/*
 * Extract the AWS error code from a JSON (`__type`/`Code`) or XML (`<Code>`)
 * error body into `out` (NUL-terminated). A leading namespace such as
 * `com.amazonaws.s3#NoSuchKey` is reduced to `NoSuchKey`.
 *
 * Returns 1 when a code was found, 0 when none is present, -EINVAL on bad args.
 */
int aws_error_code(const aws_resp *resp, char out[AWS_ERROR_CODE_LEN]);

/*
 * Detect a clock-skew-class HTTP 403 and report the local-minus-server `Date`
 * delta in seconds (positive when the local clock is ahead).
 *
 * Returns 1 when a skew-class 403 was detected and `*delta_sec` was set,
 * 0 otherwise, -EINVAL on bad arguments.
 */
int aws_clock_skew(const aws_resp *resp, long *delta_sec);

/*
 * Waiter callback: perform one poll. Returns 0 on success and sets `*done` to
 * 1 when the awaited condition holds; returns a non-zero errno-style code to
 * abort polling. A callback may itself be an `aws_request` wrapper.
 */
typedef int (*aws_waiter_fn)(aws_ctx *ctx, void *ud, int *done);

/*
 * Abort callback polled before each waiter poll. Returns non-zero when the
 * wait should stop (for example because a SIGINT/SIGTERM was recorded).
 * `user` is the caller-supplied context from aws_set_abort_hook() or
 * aws_wait_interruptible().
 */
typedef int (*aws_abort_fn)(void *user);

/*
 * Generic bounded polling loop (waiters: instance running, IP assigned, stack
 * CREATE_COMPLETE).
 *
 * Calls `fn` up to `attempts` times (attempts < 1 is EINVAL), sleeping
 * `interval_sec` seconds between polls. Returns 0 with `*timed_out == 0` when
 * the callback reports done, 0 with `*timed_out == 1` when attempts exhaust,
 * and propagates a non-zero callback return.
 *
 * Before each poll the abort hook installed on `ctx` (see
 * aws_set_abort_hook()) is consulted; a non-zero return stops the loop with
 * EINTR so callers take their normal failure path. Waiters built on this
 * function therefore inherit cancellation once the client's hook is set.
 */
int aws_wait(aws_ctx *ctx, aws_waiter_fn fn, void *ud, int attempts,
             int interval_sec, int *timed_out);

/*
 * As aws_wait(), but with an explicit abort hook for this wait only. A NULL
 * `abort_fn` disables cancellation (the per-client hook is not consulted).
 * A non-zero `abort_fn(abort_ud)` return stops the loop with EINTR before the
 * next poll; `*timed_out` stays 0.
 */
int aws_wait_interruptible(aws_ctx *ctx, aws_waiter_fn fn, void *ud,
                           aws_abort_fn abort_fn, void *abort_ud, int attempts,
                           int interval_sec, int *timed_out);

/*
 * Install (or clear, with NULL) the abort hook consulted by aws_wait() for this
 * client. The CLI sets it to `cli_abort_check` so a first SIGINT/SIGTERM
 * interrupts every cfn/ec2 waiter built on aws_wait() without per-waiter
 * changes. Safe on NULL (no-op).
 */
void aws_set_abort_hook(aws_ctx *ctx, aws_abort_fn abort_fn, void *abort_ud);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_AWS_AWS_H */
