/*
 * crypto.h — self-contained SHA-256, HMAC-SHA256 and AWS SigV4 signing.
 *
 * Public-domain-style implementation (see sha256.c / hmac.c / sigv4.c). No
 * external crypto dependency: stackctl code has zero mbedTLS API touchpoints.
 */
#ifndef STACKCTL_CORE_CRYPTO_CRYPTO_H
#define STACKCTL_CORE_CRYPTO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_SHA256_DIGEST_LEN 32
#define CRYPTO_SHA256_BLOCK_LEN 64
#define CRYPTO_SIGV4_AUTH_LEN 512

/* Streaming SHA-256 state. Treat as opaque; use the init/update/final calls. */
typedef struct crypto_sha256_ctx {
    uint32_t state[8];
    uint64_t total_bits;
    uint8_t block[CRYPTO_SHA256_BLOCK_LEN];
    size_t block_len;
} crypto_sha256_ctx;

/* One-shot SHA-256 of `len` bytes at `data` into a 32-byte digest. */
void crypto_sha256(const void *data, size_t len, uint8_t out[CRYPTO_SHA256_DIGEST_LEN]);

/* Streaming SHA-256. */
void crypto_sha256_init(crypto_sha256_ctx *ctx);
void crypto_sha256_update(crypto_sha256_ctx *ctx, const void *data, size_t len);
void crypto_sha256_final(crypto_sha256_ctx *ctx, uint8_t out[CRYPTO_SHA256_DIGEST_LEN]);

/* HMAC-SHA256 of `len` bytes at `data` under `keylen`-byte `key`. */
void crypto_hmac_sha256(const uint8_t *key, size_t keylen,
                        const void *data, size_t len,
                        uint8_t out[CRYPTO_SHA256_DIGEST_LEN]);

/*
 * Compute an AWS Signature Version 4 `Authorization` header value.
 *
 * The canonical request uses the fixed signed-header set host;x-amz-date (plus
 * x-amz-security-token when a session token is supplied). `payload_hash_or_NULL`
 * selects the payload hash line: a real hex SHA-256, or NULL for the literal
 * `UNSIGNED-PAYLOAD`.
 *
 * Returns 0 on success; a non-zero errno-style code on invalid input or when the
 * result would exceed the 512-byte output buffer.
 */
int sigv4_sign(const char *service, const char *region,
               const char *host, const char *method, const char *canonical_uri,
               const char *canonical_query, const char *payload_hash_or_NULL_for_unsigned,
               const char *amz_date, const char *amz_date_stamp,
               const char *access_key, const char *secret_key, const char *session_token_or_null,
               char out_authorization[CRYPTO_SIGV4_AUTH_LEN]);

/*
 * Compute an AWS Signature Version 4 `Authorization` header value with extra
 * signed request headers (CONTRACT Amendment 5).
 *
 * Behaves exactly like sigv4_sign() except that every entry of `extra_headers`
 * (each a `"Name: value"` line) is added to the canonical headers and the
 * SignedHeaders list. Names are lowercased and trimmed, values have outer space
 * trimmed and inner runs of spaces collapsed to one, and all headers (the fixed
 * host / x-amz-date / optional x-amz-security-token set plus the extras) are
 * sorted by lowercased name. The caller must send every signed header.
 *
 * `extra_headers` may be NULL only when `extra_header_count` is 0. A NULL array
 * with a non-zero count, an empty or duplicate name (including a duplicate of a
 * fixed header), a missing ':' or a CR/LF in a name or value returns -EINVAL.
 * Returns -ERANGE when the inputs exceed the internal buffers, matching the
 * existing crypto return style (negative errno).
 */
int sigv4_sign_with_headers(const char *service, const char *region,
                            const char *host, const char *method,
                            const char *canonical_uri, const char *canonical_query,
                            const char *payload_hash_or_NULL_for_unsigned,
                            const char *amz_date, const char *amz_date_stamp,
                            const char *access_key, const char *secret_key,
                            const char *session_token_or_null,
                            const char *const *extra_headers, size_t extra_header_count,
                            char out_authorization[CRYPTO_SIGV4_AUTH_LEN]);

#endif /* STACKCTL_CORE_CRYPTO_CRYPTO_H */
