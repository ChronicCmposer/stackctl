/* Compile-time check for the stackctl Mbed TLS client profile.
 *
 * Includes both hand-written config headers directly and asserts the profile
 * shape the vendored build relies on: TLS 1.2 + 1.3 client, X.509 parse, and
 * none of the features the spec deliberately excludes (server, DTLS, LMS).
 */

#include "configs/crypto_config.h"
#include "configs/mbedtls_config.h"

#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#error "TLS 1.2 must be enabled"
#endif
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#error "TLS 1.3 must be enabled"
#endif
#if !defined(MBEDTLS_SSL_CLI_C)
#error "client role must be enabled"
#endif
#if !defined(MBEDTLS_X509_CRT_PARSE_C)
#error "X.509 certificate parsing must be enabled"
#endif
/* libcurl's mbedTLS backend calls these unconditionally at link time:
 * filesystem-backed cert/key/CRL loaders and the public-key DER writer. */
#if !defined(MBEDTLS_FS_IO)
#error "filesystem I/O must be enabled for cert/key/CRL file loading"
#endif
#if !defined(MBEDTLS_PK_PARSE_C)
#error "public-key parsing must be enabled"
#endif
#if !defined(MBEDTLS_PK_WRITE_C)
#error "public-key writing must be enabled for mbedtls_pk_write_pubkey_der"
#endif
#if !defined(MBEDTLS_ASN1_WRITE_C)
#error "ASN.1 writing is a prerequisite of MBEDTLS_PK_WRITE_C"
#endif
#if defined(MBEDTLS_SSL_SRV_C)
#error "server role must not be enabled"
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#error "DTLS must not be enabled"
#endif
#if defined(MBEDTLS_LMS_C)
#error "LMS must not be enabled"
#endif
#if !defined(PSA_WANT_ALG_ECDH) || !defined(PSA_WANT_ALG_GCM)
#error "ECDHE and AES-GCM must be enabled"
#endif

int main(void) {
    return 0;
}
