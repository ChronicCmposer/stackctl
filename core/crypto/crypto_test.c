/*
 * crypto_test.c — unit vectors for SHA-256, HMAC-SHA256 and SigV4.
 *
 * Vectors: FIPS 180-4 (NIST SHA-256), RFC 4231 (HMAC-SHA256), and the published
 * AWS Signature Version 4 "get-vanilla" example (AKIDEXAMPLE, us-east-1,
 * 20150830T123600Z) asserting the exact Authorization header.
 */
#include "crypto.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void to_hex(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static void expect_digest(const char *name, const uint8_t digest[32], const char *expected_hex)
{
    char actual_hex[65];

    to_hex(digest, 32, actual_hex);
    if (strcmp(actual_hex, expected_hex) != 0) {
        fprintf(stderr, "FAIL %s: got %s want %s\n", name, actual_hex, expected_hex);
        failures++;
    }
}

static void expect_string(const char *name, const char *actual, const char *expected)
{
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "FAIL %s:\n  got  %s\n  want %s\n", name, actual, expected);
        failures++;
    }
}

static void test_sha256_vectors(void)
{
    uint8_t digest[32];
    crypto_sha256_ctx ctx;

    crypto_sha256("", 0, digest);
    expect_digest("sha256.empty", digest,
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    crypto_sha256("abc", 3, digest);
    expect_digest("sha256.abc", digest,
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    crypto_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
    expect_digest("sha256.448bit", digest,
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* NIST long message: one million 'a', streamed in arbitrary chunks. */
    crypto_sha256_init(&ctx);
    for (int i = 0; i < 1000; i++) {
        char fill[1000];
        memset(fill, 'a', sizeof(fill));
        crypto_sha256_update(&ctx, fill, sizeof(fill));
    }
    crypto_sha256_final(&ctx, digest);
    expect_digest("sha256.million-a", digest,
                  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void test_sha256_streaming(void)
{
    uint8_t one_shot[32];
    uint8_t streamed[32];
    crypto_sha256_ctx ctx;
    const char *message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    crypto_sha256(message, strlen(message), one_shot);
    crypto_sha256_init(&ctx);
    for (size_t i = 0; i < strlen(message); i++) {
        crypto_sha256_update(&ctx, message + i, 1);
    }
    crypto_sha256_final(&ctx, streamed);

    if (memcmp(one_shot, streamed, sizeof(one_shot)) != 0) {
        fprintf(stderr, "FAIL sha256.streaming: byte-at-a-time differs from one-shot\n");
        failures++;
    }
}

static void test_hmac_vectors(void)
{
    uint8_t digest[32];
    uint8_t key[131];

    /* RFC 4231 test case 1. */
    memset(key, 0x0b, 20);
    crypto_hmac_sha256(key, 20, "Hi There", 8, digest);
    expect_digest("hmac.tc1", digest,
                  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* RFC 4231 test case 2. */
    crypto_hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, digest);
    expect_digest("hmac.tc2", digest,
                  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    /* RFC 4231 test case 3. */
    {
        uint8_t data[50];
        memset(key, 0xaa, 20);
        memset(data, 0xdd, sizeof(data));
        crypto_hmac_sha256(key, 20, data, sizeof(data), digest);
    }
    expect_digest("hmac.tc3", digest,
                  "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* RFC 4231 test case 6: key longer than the SHA-256 block size. */
    memset(key, 0xaa, 131);
    crypto_hmac_sha256(key, 131, "Test Using Larger Than Block-Size Key - Hash Key First", 54,
                       digest);
    expect_digest("hmac.tc6", digest,
                  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    /* RFC 4231 test case 7: both key and data exceed the block size. */
    crypto_hmac_sha256(key, 131,
                       "This is a test using a larger than block-size key and a larger than "
                       "block-size data. The key needs to be hashed before being used by the "
                       "HMAC algorithm.",
                       152, digest);
    expect_digest("hmac.tc7", digest,
                  "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

/* Published aws-sig-v4-test-suite "get-vanilla" example. */
static void test_sigv4_get_vanilla(void)
{
    char authorization[CRYPTO_SIGV4_AUTH_LEN];
    int rc;

    rc = sigv4_sign("service", "us-east-1", "example.amazonaws.com", "GET", "/", "",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "20150830T123600Z", "20150830", "AKIDEXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, authorization);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.get-vanilla: rc=%d\n", rc);
        failures++;
        return;
    }
    expect_string("sigv4.get-vanilla", authorization,
                  "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/"
                  "aws4_request, SignedHeaders=host;x-amz-date, Signature="
                  "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
}

/* Same get-vanilla shape scoped to the IAM service. */
static void test_sigv4_get_vanilla_iam(void)
{
    char authorization[CRYPTO_SIGV4_AUTH_LEN];
    int rc;

    rc = sigv4_sign("iam", "us-east-1", "iam.amazonaws.com", "GET", "/",
                    "Action=ListUsers&Version=2010-05-08",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "20150830T123600Z", "20150830", "AKIDEXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, authorization);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.get-vanilla-iam: rc=%d\n", rc);
        failures++;
        return;
    }
    expect_string("sigv4.get-vanilla-iam", authorization,
                  "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/"
                  "aws4_request, SignedHeaders=host;x-amz-date, Signature="
                  "b2e4af44cfad96d9ffa3c5653674a927b9b0995c33de22e1f843745ce37c1d5e");
}

static void test_sigv4_unsigned_payload(void)
{
    char unsigned_auth[CRYPTO_SIGV4_AUTH_LEN];
    char signed_auth[CRYPTO_SIGV4_AUTH_LEN];
    int rc;

    rc = sigv4_sign("s3", "us-east-1", "s3.us-east-1.amazonaws.com", "PUT", "/bucket/key",
                    "", NULL, "20150830T123600Z", "20150830", "AKIDEXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, unsigned_auth);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.unsigned-payload: rc=%d\n", rc);
        failures++;
        return;
    }
    rc = sigv4_sign("s3", "us-east-1", "s3.us-east-1.amazonaws.com", "PUT", "/bucket/key",
                    "",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "20150830T123600Z", "20150830", "AKIDEXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, signed_auth);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.unsigned-payload baseline: rc=%d\n", rc);
        failures++;
        return;
    }
    if (strncmp(unsigned_auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/",
                strlen("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")) != 0) {
        fprintf(stderr, "FAIL sigv4.unsigned-payload: malformed header %s\n", unsigned_auth);
        failures++;
    }
    if (strcmp(unsigned_auth, signed_auth) == 0) {
        fprintf(stderr, "FAIL sigv4.unsigned-payload: UNSIGNED-PAYLOAD did not change signature\n");
        failures++;
    }
}

/* Session-token variant: SignedHeaders gains x-amz-security-token and the
 * signature changes; expected value computed independently from the SigV4
 * spec (same canonical-request shape as get-vanilla, S3 scope). */
static void test_sigv4_session_token(void)
{
    char authorization[CRYPTO_SIGV4_AUTH_LEN];
    int rc;

    rc = sigv4_sign("s3", "us-east-1", "s3.us-east-1.amazonaws.com", "GET",
                    "/bucket/key", "",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "20150830T123600Z", "20150830", "AKIDEXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "SESSIONTOKEN",
                    authorization);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.session-token: rc=%d\n", rc);
        failures++;
        return;
    }
    expect_string("sigv4.session-token", authorization,
                  "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/"
                  "aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, "
                  "Signature=53d807660daabbeb1022337ab8dfb8bc37e94569e27e8560a05e2c164fcdf6c1");
}

/*
 * Extra signed header vector (CONTRACT Amendment 5). The expected signature was
 * derived independently with Python hmac/hashlib from this canonical request:
 *   POST / <empty query>
 *   content-type:application/x-amz-json-1.1
 *   host:ssm.us-east-1.amazonaws.com
 *   x-amz-date:20150830T123600Z
 *   x-amz-target:AmazonSSM.GetParameter
 *   SignedHeaders=content-type;host;x-amz-date;x-amz-target
 *   payload hash = SHA-256("") (empty body)
 */
static void test_sigv4_extra_signed_headers(void)
{
    char authorization[CRYPTO_SIGV4_AUTH_LEN];
    const char *extras[] = {
        "X-Amz-Target: AmazonSSM.GetParameter",
        "Content-Type:   application/x-amz-json-1.1",
    };
    int rc;

    rc = sigv4_sign_with_headers(
        "ssm", "us-east-1", "ssm.us-east-1.amazonaws.com", "POST", "/", "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "20150830T123600Z", "20150830", "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, extras, 2,
        authorization);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.extra-headers: rc=%d\n", rc);
        failures++;
        return;
    }
    expect_string("sigv4.extra-headers", authorization,
                  "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/ssm/"
                  "aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
                  "Signature=f74b3ba2670f53061e04c14fc4da21c3b2e915ab1c0123658469b6b320c67f2d");
}

/* SignedHeaders must name x-amz-target and be sorted regardless of input order. */
static void test_sigv4_extra_headers_sort_and_coverage(void)
{
    char forward[CRYPTO_SIGV4_AUTH_LEN];
    char reverse[CRYPTO_SIGV4_AUTH_LEN];
    const char *forward_extras[] = {
        "X-Amz-Target: AmazonSSM.GetParameter",
        "Content-Type: application/x-amz-json-1.1",
    };
    const char *reverse_extras[] = {
        "Content-Type: application/x-amz-json-1.1",
        "X-Amz-Target: AmazonSSM.GetParameter",
    };
    const char *args[] = {"ssm", "us-east-1", "ssm.us-east-1.amazonaws.com", "POST"};
    int rc;

    rc = sigv4_sign_with_headers(
        args[0], args[1], args[2], args[3], "/", "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "20150830T123600Z", "20150830", "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, forward_extras, 2, forward);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.extra-sort: forward rc=%d\n", rc);
        failures++;
        return;
    }
    rc = sigv4_sign_with_headers(
        args[0], args[1], args[2], args[3], "/", "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "20150830T123600Z", "20150830", "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, reverse_extras, 2, reverse);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.extra-sort: reverse rc=%d\n", rc);
        failures++;
        return;
    }
    if (strstr(forward, "SignedHeaders=content-type;host;x-amz-date;x-amz-target,") == NULL) {
        fprintf(stderr, "FAIL sigv4.extra-sort: x-amz-target missing or unsorted: %s\n",
                forward);
        failures++;
    }
    if (strcmp(forward, reverse) != 0) {
        fprintf(stderr, "FAIL sigv4.extra-sort: input order changed the signature\n");
        failures++;
    }
}

/* extra_header_count == 0 must reproduce sigv4_sign() byte-for-byte. */
static void test_sigv4_no_extra_headers_matches_legacy(void)
{
    char legacy[CRYPTO_SIGV4_AUTH_LEN];
    char extended[CRYPTO_SIGV4_AUTH_LEN];
    int rc;

    rc = sigv4_sign("service", "us-east-1", "example.amazonaws.com", "GET", "/", "",
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "20150830T123600Z", "20150830", "AKIDEXAMPLE",
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, legacy);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.no-extra: legacy rc=%d\n", rc);
        failures++;
        return;
    }
    rc = sigv4_sign_with_headers(
        "service", "us-east-1", "example.amazonaws.com", "GET", "/", "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "20150830T123600Z", "20150830", "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, NULL, 0, extended);
    if (rc != 0) {
        fprintf(stderr, "FAIL sigv4.no-extra: extended rc=%d\n", rc);
        failures++;
        return;
    }
    expect_string("sigv4.no-extra-matches-legacy", extended, legacy);
}

static void test_sigv4_extra_headers_invalid(void)
{
    char authorization[CRYPTO_SIGV4_AUTH_LEN];
    const char *null_with_count[] = {NULL};
    const char *empty_name[] = {": value"};
    const char *no_colon[] = {"NoColonHere"};
    const char *cr_name[] = {"X-Amz-Target\r: value"};
    const char *lf_value[] = {"X-Amz-Target: a\nb"};
    const char *duplicate[] = {"X-Amz-Target: a", "x-amz-target: b"};
    const char *fixed_duplicate[] = {"Host: other.example.com"};
    const char *const *cases[] = {null_with_count, empty_name, no_colon, cr_name,
                                  lf_value, duplicate, fixed_duplicate};
    const size_t counts[] = {1, 1, 1, 1, 1, 2, 1};
    const char *labels[] = {"NULL array with count", "empty name", "missing colon",
                            "CR in name", "LF in value", "duplicate names",
                            "duplicate of fixed header"};

    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        int rc = sigv4_sign_with_headers(
            "ssm", "us-east-1", "ssm.us-east-1.amazonaws.com", "POST", "/", "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "20150830T123600Z", "20150830", "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", NULL, cases[i], counts[i],
            authorization);
        if (rc != -EINVAL) {
            fprintf(stderr, "FAIL sigv4.extra-invalid[%s]: rc=%d want -EINVAL\n",
                    labels[i], rc);
            failures++;
        }
    }
}

static void test_sigv4_invalid_args(void)
{
    char authorization[CRYPTO_SIGV4_AUTH_LEN];

    if (sigv4_sign(NULL, "us-east-1", "host", "GET", "/", "", NULL,
                   "20150830T123600Z", "20150830", "AKIDEXAMPLE", "secret", NULL,
                   authorization) != -EINVAL) {
        fprintf(stderr, "FAIL sigv4.invalid-args: NULL service not rejected\n");
        failures++;
    }
    if (sigv4_sign("s3", "us-east-1", NULL, "GET", "/", "", NULL,
                   "20150830T123600Z", "20150830", "AKIDEXAMPLE", "secret", NULL,
                   authorization) != -EINVAL) {
        fprintf(stderr, "FAIL sigv4.invalid-args: NULL host not rejected\n");
        failures++;
    }
    if (sigv4_sign("s3", "us-east-1", "host", "GET", "/", "", NULL,
                   "20150830T123600Z", "20150830", "AKIDEXAMPLE", "secret", NULL,
                   NULL) != -EINVAL) {
        fprintf(stderr, "FAIL sigv4.invalid-args: NULL out not rejected\n");
        failures++;
    }
}

int main(void)
{
    test_sha256_vectors();
    test_sha256_streaming();
    test_hmac_vectors();
    test_sigv4_get_vanilla();
    test_sigv4_get_vanilla_iam();
    test_sigv4_unsigned_payload();
    test_sigv4_session_token();
    test_sigv4_extra_signed_headers();
    test_sigv4_extra_headers_sort_and_coverage();
    test_sigv4_no_extra_headers_matches_legacy();
    test_sigv4_extra_headers_invalid();
    test_sigv4_invalid_args();

    if (failures != 0) {
        fprintf(stderr, "%d crypto check(s) failed\n", failures);
        return 1;
    }
    printf("all crypto vectors passed\n");
    return 0;
}
