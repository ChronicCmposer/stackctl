/**
 * @file stackctl: mbedtls_config.h
 *
 * Hand-written minimal Mbed TLS client profile for stackctl.
 *
 * Scope: TLS 1.2 + TLS 1.3 client only, X.509 certificate verification
 * (RSA and ECDSA chains), ephemeral ECDHE key exchange, SNI. Server roles,
 * DTLS, SRTP, PSK, LMS/OTS, X.509 creation/writing, ALPN and session
 * serialization are deliberately disabled. Crypto platform/algorithm
 * selection lives in the companion crypto_config.h (TF-PSA-Crypto 1.x split
 * config), which build_info.h reads before this file.
 *
 * Select it via -DMBEDTLS_CONFIG_FILE="configs/mbedtls_config.h" (see
 * //third_party/mbedtls:BUILD.mbedtls and the :config target).
 *
 * This config is consumed only by libcurl's mbedTLS backend; stackctl code has
 * no mbedTLS API touchpoints (spec §5.2).
 */

#define MBEDTLS_CONFIG_VERSION 0x04000000

/* --- Networking / timing / diagnostics ----------------------------------- */
#define MBEDTLS_NET_C
#define MBEDTLS_TIMING_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_VERSION_C
#define MBEDTLS_VERSION_FEATURES

/* --- TLS core (client only) ---------------------------------------------- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_SESSION_TICKETS

/* --- Key exchanges (TLS 1.2) --------------------------------------------- */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* --- X.509 (parse/verify only) ------------------------------------------- */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT
#define MBEDTLS_PKCS7_C

/* --- Filesystem I/O (client certificate/CRL loading) --------------------- */
/* libcurl's mbedTLS backend calls the *_parse_file/_parse_path entry points
 * (ssl_cafile/ssl_capath/ssl_crlfile); those are compiled only when
 * MBEDTLS_FS_IO is set. Kept in both configs because the X.509 library reads
 * this file while the PK file parser lives in the TF-PSA-Crypto library. */
#define MBEDTLS_FS_IO
