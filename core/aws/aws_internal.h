/*
 * aws_internal.h — unit-test seams for core/aws. NOT part of the frozen public
 * surface (aws.h). Tests include this to observe retry/backoff/URL policy
 * deterministically.
 */

#ifndef STACKCTL_CORE_AWS_AWS_INTERNAL_H
#define STACKCTL_CORE_AWS_AWS_INTERNAL_H

#include "aws.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Live client state. Opaque outside core/aws; defined here so the transport,
 * response and waiter translation units (and tests) share one layout.
 */
struct aws_ctx {
    char *access_key;
    char *secret_key;
    char *session_token;
    char *endpoint;      /* STACKCTL_ENDPOINT_URL override base, or NULL */
    unsigned backoff_base_ms;
    void *curl;          /* persistent CURL* for connection reuse */
    int curl_ready;
    /* Optional cancellation hook polled by aws_wait() before each poll. */
    int (*abort_fn)(void *user);
    void *abort_ud;
    /* Set by the transport unit on first use so the credential/context unit
     * needs no link-time reference to libcurl. */
    void (*transport_teardown)(aws_ctx *ctx);
};

/*
 * Read `[profile]` from an AWS credentials INI file. Only the three credential
 * keys are extracted. The in-module adapter stands in for the frozen core/ini
 * module, which exposes no reader; see ini_read.c for the documented lexical
 * divergences. Returns 0 with three heap-owned out-strings (token may be NULL),
 * else EINVAL/ENOENT/EFBIG/ENOMEM or another errno-style code.
 */
int aws_ini_read_profile(const char *path, const char *profile,
                         char **access_out, char **secret_out,
                         char **token_out);

/* True when an HTTP status warrants a retry (5xx or 429). */
int aws_should_retry(long status);

/* Backoff for retry index `attempt` (0-based): base * 2^attempt + jitter. */
unsigned aws_backoff_ms(unsigned base_ms, int attempt);

/*
 * Build the absolute request URL and the HTTP Host header value for `req`.
 * Both out-strings are heap-allocated; free with free(). `host_out` excludes a
 * default port (443 for https) but includes any explicit non-default port.
 * Returns 0, else EINVAL/ENOMEM.
 */
int aws_build_url(const aws_ctx *ctx, const aws_req *req,
                  char **url_out, char **host_out);

/*
 * Override the retry backoff base (milliseconds) for deterministic tests.
 * A base of 0 disables sleeping. No effect on production defaults (200 ms).
 */
void aws_test_set_backoff(aws_ctx *ctx, unsigned base_ms);

/*
 * One signed HTTP attempt handed to a transport adapter. `headers` is a
 * NULL-terminated array of complete `Name: value` lines (owned by the caller).
 */
typedef struct aws_http_attempt {
    const char *method;
    const char *url;
    const char *body;
    size_t body_len;
    const char *content_type;
    const char *const *headers;
} aws_http_attempt;

/*
 * Transport adapter: perform exactly one attempt. Return 0 once an HTTP
 * response is available (set resp->status/headers/body), or an errno-style
 * code for a transient transport failure. The retry policy lives in
 * aws_http_execute(), not in the adapter.
 */
typedef int (*aws_http_transport_fn)(aws_ctx *ctx,
                                     const aws_http_attempt *attempt,
                                     aws_resp *resp, void *ud);

/*
 * Build, sign, and execute one AWS request using `transport`, applying the
 * retry/backoff and clock-skew policy. Public aws_request() wires the libcurl
 * adapter; tests drive it with a fake adapter.
 */
int aws_http_execute(aws_ctx *ctx, const aws_req *req, aws_resp *resp,
                     aws_http_transport_fn transport, void *ud);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_AWS_AWS_INTERNAL_H */
