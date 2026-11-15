/*
 * hmac.c — HMAC-SHA256 (RFC 2104 / FIPS 198-1).
 *
 * Public-domain-style implementation built on the local SHA-256.
 */
#include "crypto.h"

#include <string.h>

#define HMAC_IPAD 0x36u
#define HMAC_OPAD 0x5cu

void crypto_hmac_sha256(const uint8_t *key, size_t keylen,
                        const void *data, size_t len,
                        uint8_t out[32])
{
    uint8_t key_block[CRYPTO_SHA256_BLOCK_LEN] = {0};
    uint8_t ipad[CRYPTO_SHA256_BLOCK_LEN];
    uint8_t opad[CRYPTO_SHA256_BLOCK_LEN];
    uint8_t inner[CRYPTO_SHA256_DIGEST_LEN];
    crypto_sha256_ctx ctx;

    if (keylen > CRYPTO_SHA256_BLOCK_LEN) {
        /* Oversized keys are hashed down to a 32-byte block prefix. */
        crypto_sha256(key, keylen, key_block);
    } else if (keylen > 0) {
        memcpy(key_block, key, keylen);
    }

    for (size_t i = 0; i < CRYPTO_SHA256_BLOCK_LEN; i++) {
        ipad[i] = key_block[i] ^ HMAC_IPAD;
        opad[i] = key_block[i] ^ HMAC_OPAD;
    }

    crypto_sha256_init(&ctx);
    crypto_sha256_update(&ctx, ipad, sizeof(ipad));
    crypto_sha256_update(&ctx, data, len);
    crypto_sha256_final(&ctx, inner);

    crypto_sha256_init(&ctx);
    crypto_sha256_update(&ctx, opad, sizeof(opad));
    crypto_sha256_update(&ctx, inner, sizeof(inner));
    crypto_sha256_final(&ctx, out);

    memset(key_block, 0, sizeof(key_block));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(inner, 0, sizeof(inner));
}
