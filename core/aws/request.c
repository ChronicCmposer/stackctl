/*
 * request.c — transport-independent request policy: canonical URL, SigV4
 * signing, retry/backoff, and clock-skew diagnosis.
 *
 * The actual HTTP send is injected as an `aws_http_transport_fn`, so this unit
 * links without libcurl and the retry/signing rules are unit-testable with a
 * fake adapter. http.c provides the libcurl adapter and public aws_request().
 */

#include "aws_internal.h"
#include "../crypto/crypto.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Only genuinely transient transport failures may consume another attempt.
 * Permanent errors (bad arguments, permission, protocol) would fail the same
 * way every time, so retrying them only delays the diagnostic.
 */
static int transport_error_retryable(int err)
{
    switch (err) {
    case ETIMEDOUT:
    case ECONNRESET:
    case ECONNREFUSED:
    case EPIPE:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTUNREACH:
    case EAGAIN:
    case EINTR:
        return 1;
    default:
        return 0;
    }
}

static void sleep_ms(unsigned ms)
{
    if (ms == 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/* Canonical URI (path only, no query) of an absolute URL. */
static char *canonical_uri_of(const char *url)
{
    const char *scheme = strstr(url, "://");
    const char *path = scheme != NULL ? scheme + 3 : url;
    path = strchr(path, '/');
    if (path == NULL) {
        path = "/";
    }
    size_t len = strcspn(path, "?");
    char *out = malloc(len + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, path, len);
    out[len] = '\0';
    return out;
}

static void hex_encode(const uint8_t digest[CRYPTO_SHA256_DIGEST_LEN],
                       char out[CRYPTO_SHA256_DIGEST_LEN * 2 + 1])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < CRYPTO_SHA256_DIGEST_LEN; i++) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 0x0f];
    }
    out[CRYPTO_SHA256_DIGEST_LEN * 2] = '\0';
}

static void free_lines(char **lines)
{
    if (lines == NULL) {
        return;
    }
    for (size_t i = 0; lines[i] != NULL; i++) {
        free(lines[i]);
    }
    free(lines);
}

/* Append one heap-owned header line to a NULL-terminated string array. */
static int append_line(char ***lines, size_t *count, const char *line)
{
    char **grown = realloc(*lines, (*count + 2) * sizeof(*grown));
    if (grown == NULL) {
        return ENOMEM;
    }
    *lines = grown;
    char *copy = strdup(line);
    if (copy == NULL) {
        return ENOMEM;
    }
    grown[*count] = copy;
    (*count)++;
    grown[*count] = NULL;
    return 0;
}

static int append_format(char ***lines, size_t *count, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    va_list copy;
    va_copy(copy, ap);
    int need = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (need < 0) {
        va_end(ap);
        return EINVAL;
    }
    char *buffer = malloc((size_t)need + 1);
    if (buffer == NULL) {
        va_end(ap);
        return ENOMEM;
    }
    vsnprintf(buffer, (size_t)need + 1, fmt, ap);
    va_end(ap);
    int rc = append_line(lines, count, buffer);
    free(buffer);
    return rc;
}

/*
 * Validate one caller-supplied `"Name: value"` extra header line. A missing
 * ':', an empty name or any CR/LF makes the request unbuildable; reject it
 * loudly rather than emit a malformed or unsafely framed header.
 */
static int validate_extra_header(const char *line)
{
    if (line == NULL) {
        return EINVAL;
    }
    const char *colon = strchr(line, ':');
    if (colon == NULL) {
        return EINVAL;
    }
    for (const char *p = line; *p != '\0'; p++) {
        if (*p == '\r' || *p == '\n') {
            return EINVAL;
        }
    }
    for (const char *p = line; p < colon; p++) {
        if (*p != ' ' && *p != '\t') {
            return 0;
        }
    }
    return EINVAL;
}

static int ascii_name_equal(const char *name, size_t len, const char *want)
{
    size_t want_len = strlen(want);
    if (len != want_len) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (c != want[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * Headers the signer must cover: every `x-amz-*` header (AWS rejects an
 * unsigned x-amz-* header) plus `content-type` when it is supplied as an extra.
 */
static int extra_header_is_signed(const char *line)
{
    const char *colon = strchr(line, ':');
    const char *name = line;
    size_t len = (size_t)(colon - line);
    while (len > 0 && (name[len - 1] == ' ' || name[len - 1] == '\t')) {
        len--;
    }
    while (len > 0 && (*name == ' ' || *name == '\t')) {
        name++;
        len--;
    }
    if (len >= 6 && ascii_name_equal(name, 6, "x-amz-")) {
        return 1;
    }
    return ascii_name_equal(name, len, "content-type");
}

/*
 * Sign `req` for `url`/`host`, producing the outgoing header line array.
 * Returns 0 or an errno-style code.
 */
static int build_signed_headers(const aws_ctx *ctx, const aws_req *req,
                                const char *url, const char *host,
                                char ***out, size_t *out_count)
{
    char amz_date[17];
    char stamp[9];
    time_t now = time(NULL);
    struct tm tm;
    if (gmtime_r(&now, &tm) == NULL) {
        return EIO;
    }
    if (strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm) == 0 ||
        strftime(stamp, sizeof(stamp), "%Y%m%d", &tm) == 0) {
        return EIO;
    }

    char payload_hash[CRYPTO_SHA256_DIGEST_LEN * 2 + 1];
    if (!req->unsigned_payload) {
        static const uint8_t empty = 0;
        const void *data = req->body != NULL ? req->body : &empty;
        uint8_t digest[CRYPTO_SHA256_DIGEST_LEN];
        crypto_sha256(data, req->body_len, digest);
        hex_encode(digest, payload_hash);
    }

    if (req->extra_header_count > 0 && req->extra_headers == NULL) {
        return EINVAL;
    }

    /*
     * Validate every extra line up front and collect the ones the signer must
     * cover. All extras are still emitted on the wire below.
     */
    const char **signed_extras = NULL;
    size_t signed_count = 0;
    if (req->extra_header_count > 0) {
        signed_extras = malloc(req->extra_header_count * sizeof(*signed_extras));
        if (signed_extras == NULL) {
            return ENOMEM;
        }
        for (size_t i = 0; i < req->extra_header_count; i++) {
            int bad = validate_extra_header(req->extra_headers[i]);
            if (bad != 0) {
                free(signed_extras);
                return bad;
            }
            if (extra_header_is_signed(req->extra_headers[i])) {
                signed_extras[signed_count++] = req->extra_headers[i];
            }
        }
    }

    char *canonical_uri = canonical_uri_of(url);
    if (canonical_uri == NULL) {
        free(signed_extras);
        return ENOMEM;
    }
    char authorization[CRYPTO_SIGV4_AUTH_LEN];
    int rc = sigv4_sign_with_headers(
        req->service, req->region, host, req->method, canonical_uri,
        req->query != NULL ? req->query : "",
        req->unsigned_payload ? NULL : payload_hash, amz_date, stamp,
        ctx->access_key, ctx->secret_key, ctx->session_token, signed_extras,
        signed_count, authorization);
    free(canonical_uri);
    free(signed_extras);
    if (rc != 0) {
        return rc;
    }

    char **lines = NULL;
    size_t count = 0;
    rc = append_format(&lines, &count, "Authorization: %s", authorization);
    if (rc == 0) {
        rc = append_format(&lines, &count, "x-amz-date: %s", amz_date);
    }
    if (rc == 0) {
        rc = append_format(&lines, &count, "x-amz-content-sha256: %s",
                           req->unsigned_payload ? "UNSIGNED-PAYLOAD"
                                                 : payload_hash);
    }
    if (rc == 0 && ctx->session_token != NULL) {
        rc = append_format(&lines, &count, "x-amz-security-token: %s",
                           ctx->session_token);
    }
    if (rc == 0 && req->content_type != NULL) {
        rc = append_format(&lines, &count, "Content-Type: %s",
                           req->content_type);
    }
    for (size_t i = 0; rc == 0 && i < req->extra_header_count; i++) {
        rc = append_line(&lines, &count, req->extra_headers[i]);
    }
    if (rc != 0) {
        free_lines(lines);
        return rc;
    }
    *out = lines;
    *out_count = count;
    return 0;
}

int aws_http_execute(aws_ctx *ctx, const aws_req *req, aws_resp *resp,
                     aws_http_transport_fn transport, void *ud)
{
    if (ctx == NULL || req == NULL || resp == NULL || transport == NULL) {
        return EINVAL;
    }
    if (req->service == NULL || req->region == NULL || req->method == NULL ||
        req->path == NULL) {
        return EINVAL;
    }

    aws_resp_free(resp);
    int last_error = EIO;

    for (int attempt = 0; attempt < AWS_MAX_ATTEMPTS; attempt++) {
        aws_resp_free(resp);

        char *url = NULL;
        char *host = NULL;
        int rc = aws_build_url(ctx, req, &url, &host);
        if (rc != 0) {
            return rc;
        }
        char **headers = NULL;
        size_t header_count = 0;
        rc = build_signed_headers(ctx, req, url, host, &headers, &header_count);
        if (rc != 0) {
            free(url);
            free(host);
            return rc;
        }
        (void)header_count;

        aws_http_attempt call = {
            .method = req->method,
            .url = url,
            .body = req->body,
            .body_len = req->body_len,
            .content_type = req->content_type,
            .headers = (const char *const *)headers,
        };
        rc = transport(ctx, &call, resp, ud);
        free(url);
        free(host);
        free_lines(headers);

        if (rc != 0) {
            last_error = rc;
            if (transport_error_retryable(rc) &&
                attempt + 1 < AWS_MAX_ATTEMPTS) {
                sleep_ms(aws_backoff_ms(ctx->backoff_base_ms, attempt));
                continue;
            }
            aws_resp_free(resp);
            return last_error;
        }

        if (aws_should_retry(resp->status) &&
            attempt + 1 < AWS_MAX_ATTEMPTS) {
            sleep_ms(aws_backoff_ms(ctx->backoff_base_ms, attempt));
            continue;
        }

        long delta = 0;
        if (aws_clock_skew(resp, &delta) == 1) {
            fprintf(stderr,
                    "stackctl: AWS clock skew: local clock is %lds %s the "
                    "server Date; check NTP (never auto-adjusted)\n",
                    delta < 0 ? -delta : delta,
                    delta < 0 ? "behind" : "ahead of");
        }
        return 0;
    }

    return last_error;
}
