/**
 * @file stackctl: crypto_config.h
 *
 * Hand-written minimal TF-PSA-Crypto 1.1.1 (PSA) configuration for stackctl,
 * companion to mbedtls_config.h.
 *
 * Scope: exactly the primitives a TLS 1.2/1.3 *client* with X.509
 * verification needs — AES-GCM/CBC, ChaCha20-Poly1305, HMAC, SHA-1/224/256/
 * 384/512, TLS 1.2 PRF, ECDHE (P-256/384/521, X25519), ECDSA and RSA-PSS /
 * RSA-PKCS1-v1_5 signature verification. No key storage, no MD5/RIPEMD/SHA3,
 * no post-quantum (LMS/ML-DSA), no ARIA/Camellia.
 *
 * Select it via -D TF_PSA_CRYPTO_CONFIG_FILE="configs/crypto_config.h" (see
 * //third_party/mbedtls:BUILD.mbedtls and the :config target).
 */

#define TF_PSA_CRYPTO_CONFIG_VERSION 0x01000000

/* --- Platform / crypto framework features -------------------------------- */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CLIENT
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY

/* --- ASN.1 / PEM / PK used by X.509 parsing ------------------------------ */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_MD_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_PARSE_EC_EXTENDED
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_ECP_NIST_OPTIM

/* libcurl's mbedTLS backend loads keys/certs/CRLs from the filesystem
 * (mbedtls_pk_parse_keyfile, mbedtls_x509_*_parse_file/_parse_path), and the
 * PK file parser is compiled into the TF-PSA-Crypto library, which only sees
 * this config. MBEDTLS_ASN1_WRITE_C above is a direct prerequisite of
 * MBEDTLS_PK_WRITE_C (mbedtls_pk_write_pubkey_der). */
#define MBEDTLS_FS_IO

/* --- AEAD / cipher algorithms -------------------------------------------- */
#define PSA_WANT_ALG_CBC_NO_PADDING             1
#define PSA_WANT_ALG_CHACHA20_POLY1305          1
#define PSA_WANT_ALG_GCM                        1

/* --- Hashes / MAC / KDF -------------------------------------------------- */
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_SHA_1                      1
#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_SHA_512                    1
#define PSA_WANT_ALG_TLS12_PRF                  1

/* --- Key agreement / signatures ------------------------------------------ */
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
#define PSA_WANT_ALG_RSA_PSS                    1
#define PSA_WANT_ALG_RSA_OAEP                   1

/* --- Key types ----------------------------------------------------------- */
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_CHACHA20              1
#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC    1

/* --- ECC curves ---------------------------------------------------------- */
#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_ECC_SECP_R1_384                1
#define PSA_WANT_ECC_SECP_R1_521                1
