/*
 * sigv4.c — AWS Signature Version 4 request signing.
 *
 * Builds the canonical request, the string-to-sign, derives the signing key
 * (kDate -> kRegion -> kService -> kSigning) and emits the Authorization header
 * value. Hand-rolled and SigV4a-ready in structure, but v1 scope only.
 *
 * sigv4_sign() keeps the historical fixed signed-header set. The additive
 * sigv4_sign_with_headers() (CONTRACT Amendment 5) signs caller-supplied extra
 * `"Name: value"` header lines as well; both share one canonical-request
 * builder so the two paths can never drift.
 */
#include "crypto.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIGV4_ALGORITHM "AWS4-HMAC-SHA256"
#define SIGV4_TERMINATOR "aws4_request"
#define SIGV4_UNSIGNED_PAYLOAD "UNSIGNED-PAYLOAD"

#define CANONICAL_HEADERS_MAX 8192
#define CANONICAL_REQUEST_MAX 16384
#define STRING_TO_SIGN_MAX 2048
#define SCOPE_MAX 512

/* One parsed/normalised header for the extra-header signer. */
#define SIGV4_MAX_HEADERS 64
#define SIGV4_HEADER_NAME_MAX 128
#define SIGV4_HEADER_VALUE_MAX 1024

typedef struct sigv4_header {
    char name[SIGV4_HEADER_NAME_MAX];
    char value[SIGV4_HEADER_VALUE_MAX];
} sigv4_header;

/* Append formatted text to buf at *off, failing loudly on truncation. */
static int append(char *buf, size_t cap, size_t *off, const char *fmt, ...)
{
    va_list ap;
    int written;

    va_start(ap, fmt);
    written = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);

    if (written < 0 || (size_t)written >= cap - *off) {
        return -ERANGE;
    }
    *off += (size_t)written;
    return 0;
}

static void encode_hex(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static char ascii_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static int is_http_space(char c)
{
    return c == ' ' || c == '\t';
}

/*
 * Parse one `"Name: value"` line into `out`: lowercase/trim the name, trim the
 * value and collapse internal runs of spaces to one. Rejects a missing ':' and
 * any CR/LF. Returns 0, -EINVAL or -ERANGE.
 */
static int parse_header_line(const char *line, sigv4_header *out)
{
    if (line == NULL) {
        return -EINVAL;
    }
    for (const char *p = line; *p != '\0'; p++) {
        if (*p == '\r' || *p == '\n') {
            return -EINVAL;
        }
    }

    const char *colon = strchr(line, ':');
    if (colon == NULL) {
        return -EINVAL;
    }

    const char *name_begin = line;
    const char *name_end = colon;
    while (name_begin < name_end && is_http_space(*name_begin)) {
        name_begin++;
    }
    while (name_end > name_begin && is_http_space(name_end[-1])) {
        name_end--;
    }
    size_t name_len = (size_t)(name_end - name_begin);
    if (name_len == 0) {
        return -EINVAL;
    }
    if (name_len >= sizeof(out->name)) {
        return -ERANGE;
    }
    for (size_t i = 0; i < name_len; i++) {
        out->name[i] = ascii_lower(name_begin[i]);
    }
    out->name[name_len] = '\0';

    size_t value_len = 0;
    int pending_space = 0;
    for (const char *p = colon + 1; *p != '\0'; p++) {
        if (is_http_space(*p)) {
            pending_space = 1;
            continue;
        }
        if (pending_space && value_len > 0) {
            if (value_len >= sizeof(out->value) - 1) {
                return -ERANGE;
            }
            out->value[value_len++] = ' ';
        }
        pending_space = 0;
        if (value_len >= sizeof(out->value) - 1) {
            return -ERANGE;
        }
        out->value[value_len++] = *p;
    }
    out->value[value_len] = '\0';
    return 0;
}

/* Copy a trusted fixed header (already lowercase name) without collapsing. */
static int set_raw_header(sigv4_header *out, const char *name, const char *value)
{
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    if (name_len >= sizeof(out->name) || value_len >= sizeof(out->value)) {
        return -ERANGE;
    }
    memcpy(out->name, name, name_len + 1);
    memcpy(out->value, value, value_len + 1);
    return 0;
}

static int compare_headers(const void *lhs, const void *rhs)
{
    const sigv4_header *a = lhs;
    const sigv4_header *b = rhs;
    return strcmp(a->name, b->name);
}

/*
 * Compute the Authorization header from already-built canonical headers and
 * SignedHeaders strings. Shared by sigv4_sign() and sigv4_sign_with_headers().
 */
static int sigv4_finish(const char *service, const char *region,
                        const char *method, const char *canonical_uri,
                        const char *canonical_query,
                        const char *payload_hash_or_NULL_for_unsigned,
                        const char *amz_date, const char *amz_date_stamp,
                        const char *access_key, const char *secret_key,
                        const char *canonical_headers, const char *signed_headers,
                        char out_authorization[CRYPTO_SIGV4_AUTH_LEN])
{
    const char *payload_hash;
    char canonical_request[CANONICAL_REQUEST_MAX];
    char string_to_sign[STRING_TO_SIGN_MAX];
    char scope[SCOPE_MAX];
    char request_hash_hex[CRYPTO_SHA256_DIGEST_LEN * 2 + 1];
    char signature_hex[CRYPTO_SHA256_DIGEST_LEN * 2 + 1];
    char signing_key_seed[512];
    uint8_t digest[CRYPTO_SHA256_DIGEST_LEN];
    uint8_t k_date[CRYPTO_SHA256_DIGEST_LEN];
    uint8_t k_region[CRYPTO_SHA256_DIGEST_LEN];
    uint8_t k_service[CRYPTO_SHA256_DIGEST_LEN];
    uint8_t k_signing[CRYPTO_SHA256_DIGEST_LEN];
    size_t request_off = 0;
    size_t scope_off = 0;
    size_t sts_off = 0;
    int seed_len;
    int rc;
    int written;

    payload_hash = (payload_hash_or_NULL_for_unsigned != NULL)
                       ? payload_hash_or_NULL_for_unsigned
                       : SIGV4_UNSIGNED_PAYLOAD;

    rc = append(canonical_request, sizeof(canonical_request), &request_off,
                "%s\n%s\n%s\n%s\n%s\n%s",
                method, canonical_uri, canonical_query, canonical_headers,
                signed_headers, payload_hash);
    if (rc != 0) {
        return rc;
    }

    crypto_sha256(canonical_request, request_off, digest);
    encode_hex(digest, sizeof(digest), request_hash_hex);

    rc = append(scope, sizeof(scope), &scope_off, "%s/%s/%s/%s",
                amz_date_stamp, region, service, SIGV4_TERMINATOR);
    if (rc != 0) {
        return rc;
    }

    rc = append(string_to_sign, sizeof(string_to_sign), &sts_off,
                "%s\n%s\n%s\n%s", SIGV4_ALGORITHM, amz_date, scope, request_hash_hex);
    if (rc != 0) {
        return rc;
    }

    seed_len = snprintf(signing_key_seed, sizeof(signing_key_seed), "AWS4%s", secret_key);
    if (seed_len < 0 || (size_t)seed_len >= sizeof(signing_key_seed)) {
        return -ERANGE;
    }

    crypto_hmac_sha256((const uint8_t *)signing_key_seed, (size_t)seed_len,
                       amz_date_stamp, strlen(amz_date_stamp), k_date);
    crypto_hmac_sha256(k_date, sizeof(k_date), region, strlen(region), k_region);
    crypto_hmac_sha256(k_region, sizeof(k_region), service, strlen(service), k_service);
    crypto_hmac_sha256(k_service, sizeof(k_service), SIGV4_TERMINATOR,
                       strlen(SIGV4_TERMINATOR), k_signing);
    crypto_hmac_sha256(k_signing, sizeof(k_signing), string_to_sign, sts_off, digest);
    encode_hex(digest, sizeof(digest), signature_hex);

    written = snprintf(out_authorization, CRYPTO_SIGV4_AUTH_LEN,
                       "%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
                       SIGV4_ALGORITHM, access_key, scope, signed_headers, signature_hex);
    if (written < 0 || written >= CRYPTO_SIGV4_AUTH_LEN) {
        out_authorization[0] = '\0';
        return -ERANGE;
    }

    return 0;
}

/* Shared boundary guard for both public signing entry points. */
static int validate_sign_args(const char *service, const char *region,
                              const char *host, const char *method,
                              const char *canonical_uri, const char *canonical_query,
                              const char *amz_date, const char *amz_date_stamp,
                              const char *access_key, const char *secret_key,
                              const char *out_authorization)
{
    if (service == NULL || region == NULL || host == NULL || method == NULL ||
        canonical_uri == NULL || canonical_query == NULL || amz_date == NULL ||
        amz_date_stamp == NULL || access_key == NULL || secret_key == NULL ||
        out_authorization == NULL) {
        return -EINVAL;
    }
    return 0;
}

int sigv4_sign(const char *service, const char *region,
               const char *host, const char *method, const char *canonical_uri,
               const char *canonical_query, const char *payload_hash_or_NULL_for_unsigned,
               const char *amz_date, const char *amz_date_stamp,
               const char *access_key, const char *secret_key, const char *session_token_or_null,
               char out_authorization[512])
{
    const char *signed_headers;
    char canonical_headers[CANONICAL_HEADERS_MAX];
    size_t headers_off = 0;
    int rc;

    rc = validate_sign_args(service, region, host, method, canonical_uri,
                            canonical_query, amz_date, amz_date_stamp, access_key,
                            secret_key, out_authorization);
    if (rc != 0) {
        return rc;
    }

    signed_headers = (session_token_or_null != NULL)
                         ? "host;x-amz-date;x-amz-security-token"
                         : "host;x-amz-date";

    rc = append(canonical_headers, sizeof(canonical_headers), &headers_off,
                "host:%s\nx-amz-date:%s\n", host, amz_date);
    if (rc != 0) {
        return rc;
    }
    if (session_token_or_null != NULL) {
        rc = append(canonical_headers, sizeof(canonical_headers), &headers_off,
                    "x-amz-security-token:%s\n", session_token_or_null);
        if (rc != 0) {
            return rc;
        }
    }

    return sigv4_finish(service, region, method, canonical_uri, canonical_query,
                        payload_hash_or_NULL_for_unsigned, amz_date, amz_date_stamp,
                        access_key, secret_key, canonical_headers, signed_headers,
                        out_authorization);
}

int sigv4_sign_with_headers(const char *service, const char *region,
                            const char *host, const char *method,
                            const char *canonical_uri, const char *canonical_query,
                            const char *payload_hash_or_NULL_for_unsigned,
                            const char *amz_date, const char *amz_date_stamp,
                            const char *access_key, const char *secret_key,
                            const char *session_token_or_null,
                            const char *const *extra_headers, size_t extra_header_count,
                            char out_authorization[CRYPTO_SIGV4_AUTH_LEN])
{
    sigv4_header headers[SIGV4_MAX_HEADERS];
    char canonical_headers[CANONICAL_HEADERS_MAX] = {0};
    char signed_headers[CANONICAL_HEADERS_MAX] = {0};
    size_t headers_off = 0;
    size_t signed_off = 0;
    size_t count = 0;
    int rc;

    rc = validate_sign_args(service, region, host, method, canonical_uri,
                            canonical_query, amz_date, amz_date_stamp, access_key,
                            secret_key, out_authorization);
    if (rc != 0) {
        return rc;
    }
    if (extra_header_count > 0 && extra_headers == NULL) {
        return -EINVAL;
    }

    /* Fixed signed headers. */
    if ((rc = set_raw_header(&headers[count++], "host", host)) != 0 ||
        (rc = set_raw_header(&headers[count++], "x-amz-date", amz_date)) != 0) {
        return rc;
    }
    if (session_token_or_null != NULL) {
        rc = set_raw_header(&headers[count++], "x-amz-security-token", session_token_or_null);
        if (rc != 0) {
            return rc;
        }
    }

    /* Caller-supplied extra headers. */
    for (size_t i = 0; i < extra_header_count; i++) {
        if (count >= SIGV4_MAX_HEADERS) {
            return -ERANGE;
        }
        rc = parse_header_line(extra_headers[i], &headers[count]);
        if (rc != 0) {
            return rc;
        }
        count++;
    }

    qsort(headers, count, sizeof(headers[0]), compare_headers);
    for (size_t i = 1; i < count; i++) {
        if (strcmp(headers[i - 1].name, headers[i].name) == 0) {
            return -EINVAL;
        }
    }

    for (size_t i = 0; i < count; i++) {
        rc = append(canonical_headers, sizeof(canonical_headers), &headers_off,
                    "%s:%s\n", headers[i].name, headers[i].value);
        if (rc != 0) {
            return rc;
        }
        rc = append(signed_headers, sizeof(signed_headers), &signed_off,
                    (i == 0) ? "%s" : ";%s", headers[i].name);
        if (rc != 0) {
            return rc;
        }
    }

    return sigv4_finish(service, region, method, canonical_uri, canonical_query,
                        payload_hash_or_NULL_for_unsigned, amz_date, amz_date_stamp,
                        access_key, secret_key, canonical_headers, signed_headers,
                        out_authorization);
}
