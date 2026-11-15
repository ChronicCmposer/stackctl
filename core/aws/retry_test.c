/*
 * retry_test.c — transport-independent request-policy tests using a fake
 * transport adapter. Verifies SigV4 header construction, UNSIGNED-PAYLOAD,
 * retry on 5xx, no-retry on 4xx, transient-failure retry, exhaustion, and
 * argument validation without linking libcurl.
 */

#include "aws.h"
#include "aws_internal.h"
#include "yyjson.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

typedef struct {
    int calls;
    int status_count;
    long statuses[8];
    int error_count;          /* first N calls fail with error_errno */
    int error_errno;          /* errno returned by the failing calls */
    int capture;
    char url[512];
    char headers[4096];
    char body[512];
} fake_state;

static int fake_transport(aws_ctx *ctx, const aws_http_attempt *attempt,
                          aws_resp *resp, void *ud)
{
    (void)ctx;
    fake_state *st = ud;
    int call = st->calls++;
    if (st->capture) {
        snprintf(st->url, sizeof(st->url), "%s", attempt->url);
        snprintf(st->body, sizeof(st->body), "%.*s",
                 (int)attempt->body_len,
                 attempt->body != NULL ? (const char *)attempt->body : "");
        st->headers[0] = '\0';
        for (size_t i = 0; attempt->headers[i] != NULL; i++) {
            size_t used = strlen(st->headers);
            snprintf(st->headers + used, sizeof(st->headers) - used, "%s\n",
                     attempt->headers[i]);
        }
    }
    if (call < st->error_count) {
        return st->error_errno != 0 ? st->error_errno : ECONNRESET;
    }
    long status = 200;
    if (st->status_count > 0) {
        int index = call - st->error_count;
        if (index >= st->status_count) {
            index = st->status_count - 1;
        }
        status = st->statuses[index];
    }
    resp->status = status;
    resp->body = strdup("{\"fake\":true}");
    resp->body_len = strlen(resp->body);
    return 0;
}

static char *make_home(void)
{
    char *home = strdup("/tmp/stackctl-aws-retry-XXXXXX");
    if (home == NULL || mkdtemp(home) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    char dir[512];
    char path[512];
    snprintf(dir, sizeof(dir), "%s/.aws", home);
    mkdir(dir, 0700);
    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror("fopen credentials");
        exit(2);
    }
    fputs("[proj]\n"
          "aws_access_key_id = AKIAPROJ\n"
          "aws_secret_access_key = secret-proj\n"
          "aws_session_token = token-proj\n",
          f);
    fclose(f);
    return home;
}

static aws_ctx *make_ctx(void)
{
    char *home = make_home();
    setenv("HOME", home, 1);
    unsetenv("STACKCTL_ENDPOINT_URL");
    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == 0, "aws_init(proj)");
    if (ctx != NULL) {
        aws_test_set_backoff(ctx, 0);
    }
    free(home);
    return ctx;
}

static int headers_contain(const fake_state *st, const char *needle)
{
    return strstr(st->headers, needle) != NULL;
}

static void test_signed_request_headers(void)
{
    aws_ctx *ctx = make_ctx();
    fake_state st = {.status_count = 1, .statuses = {200}, .capture = 1};
    aws_resp resp = {0};
    aws_req req = {
        .service = "ec2",
        .region = "us-east-1",
        .method = "GET",
        .path = "/",
        .query = "Action=DescribeInstances&Version=2016-11-15",
    };
    int rc = aws_http_execute(ctx, &req, &resp, fake_transport, &st);
    CHECK(rc == 0, "fake transport request succeeds");
    CHECK(st.calls == 1, "one attempt for 200");
    CHECK(strcmp(st.url,
        "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15") == 0,
        "signed URL built");
    CHECK(headers_contain(&st, "Authorization: AWS4-HMAC-SHA256 "), "SigV4 auth");
    CHECK(headers_contain(&st, "Credential=AKIAPROJ/"), "access key used");
    CHECK(headers_contain(&st, "x-amz-date: "), "x-amz-date header");
    CHECK(headers_contain(&st, "x-amz-security-token: token-proj"),
          "session token header");
    CHECK(!headers_contain(&st, "UNSIGNED-PAYLOAD"), "signed payload for ec2");
    CHECK(resp.status == 200, "status surfaced");
    aws_resp_free(&resp);
    aws_free(ctx);
}

static void test_unsigned_payload_retry(void)
{
    aws_ctx *ctx = make_ctx();
    fake_state st = {
        .status_count = 3,
        .statuses = {503, 503, 200},
        .capture = 1,
    };
    aws_resp resp = {0};
    aws_req req = {
        .service = "s3",
        .region = "us-east-1",
        .method = "PUT",
        .path = "/bucket/key",
        .body = "hello",
        .body_len = 5,
        .content_type = "application/octet-stream",
        .unsigned_payload = 1,
    };
    int rc = aws_http_execute(ctx, &req, &resp, fake_transport, &st);
    CHECK(rc == 0, "retried request returns 0");
    CHECK(st.calls == 3, "two 503s then success = 3 attempts");
    CHECK(resp.status == 200, "final status 200");
    CHECK(headers_contain(&st, "x-amz-content-sha256: UNSIGNED-PAYLOAD"),
          "S3 unsigned payload");
    CHECK(headers_contain(&st, "Content-Type: application/octet-stream"),
          "content type forwarded");
    CHECK(strcmp(st.body, "hello") == 0, "body forwarded");
    aws_resp_free(&resp);
    aws_free(ctx);
}

/* CONTRACT Amendment 5: extra x-amz-* headers are sent and signed. */
static void test_extra_signed_headers(void)
{
    aws_ctx *ctx = make_ctx();
    fake_state st = {.status_count = 1, .statuses = {200}, .capture = 1};
    aws_resp resp = {0};
    const char *extras[] = {
        "X-Amz-Target: AmazonSSM.GetParameter",
        "Content-Type: application/x-amz-json-1.1",
        "X-Untraced: opaque",
    };
    aws_req req = {
        .service = "ssm",
        .region = "us-east-1",
        .method = "POST",
        .path = "/",
        .body = "{}",
        .body_len = 2,
        .extra_headers = extras,
        .extra_header_count = 3,
        .unsigned_payload = 0,
    };
    int rc = aws_http_execute(ctx, &req, &resp, fake_transport, &st);
    CHECK(rc == 0, "extra-header request succeeds");
    CHECK(st.calls == 1, "one attempt for 200");
    CHECK(headers_contain(&st, "X-Amz-Target: AmazonSSM.GetParameter"),
          "x-amz-target emitted on the wire");
    CHECK(headers_contain(&st, "Content-Type: application/x-amz-json-1.1"),
          "extra content-type emitted on the wire");
    CHECK(headers_contain(&st, "X-Untraced: opaque"),
          "non-amz extra emitted on the wire");
    CHECK(!headers_contain(&st, "UNSIGNED-PAYLOAD"),
          "unsigned_payload 0 signs the body");
    CHECK(headers_contain(
              &st,
              "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;"
              "x-amz-target"),
          "SignedHeaders covers x-amz-target and sorts extras");
    CHECK(!headers_contain(&st, "x-untraced;"),
          "non-amz extra is not signed");
    aws_resp_free(&resp);
    aws_free(ctx);
}

/* A malformed extra header line fails fast, before any attempt is made. */
static void test_invalid_extra_header_rejected(void)
{
    aws_ctx *ctx = make_ctx();
    fake_state st = {.status_count = 1, .statuses = {200}, .capture = 1};
    aws_resp resp = {0};
    const char *no_colon[] = {"X-Amz-Target AmazonSSM.GetParameter"};
    aws_req req = {
        .service = "ssm",
        .region = "us-east-1",
        .method = "POST",
        .path = "/",
        .extra_headers = no_colon,
        .extra_header_count = 1,
    };
    int rc = aws_http_execute(ctx, &req, &resp, fake_transport, &st);
    CHECK(rc == EINVAL, "missing ':' in extra header rejected");
    CHECK(st.calls == 0, "no attempt for an invalid extra header");
    aws_resp_free(&resp);
    aws_free(ctx);
}

static void test_no_retry_on_4xx(void)
{
    aws_ctx *ctx = make_ctx();
    fake_state st = {.status_count = 1, .statuses = {400}, .capture = 1};
    aws_resp resp = {0};
    aws_req req = {.service = "ec2", .region = "us-east-1",
                   .method = "GET", .path = "/"};
    int rc = aws_http_execute(ctx, &req, &resp, fake_transport, &st);
    CHECK(rc == 0, "4xx surfaces as an HTTP response");
    CHECK(st.calls == 1, "400 is not retried");
    CHECK(resp.status == 400, "400 status surfaced");
    aws_resp_free(&resp);
    aws_free(ctx);
}

static void test_transport_error_retry_and_exhaustion(void)
{
    aws_ctx *ctx = make_ctx();
    fake_state st = {.status_count = 0, .error_count = 2,
                     .error_errno = ECONNRESET};
    aws_resp resp = {0};
    aws_req req = {.service = "ec2", .region = "us-east-1",
                   .method = "GET", .path = "/"};
    int rc = aws_http_execute(ctx, &req, &resp, fake_transport, &st);
    CHECK(rc == 0, "transient failures then success returns 0");
    CHECK(st.calls == 3, "two transport failures then success");
    CHECK(resp.status == 200, "success status after transport retries");
    aws_resp_free(&resp);

    fake_state doomed = {.status_count = 0, .error_count = 99,
                         .error_errno = ETIMEDOUT};
    resp = (aws_resp){0};
    rc = aws_http_execute(ctx, &req, &resp, fake_transport, &doomed);
    CHECK(rc == ETIMEDOUT, "exhausted transient error propagated");
    CHECK(doomed.calls == AWS_MAX_ATTEMPTS, "retries capped at max attempts");
    CHECK(resp.status == 0, "no status after transport failure");
    aws_resp_free(&resp);

    /* A permanent transport errno must fail fast, not burn six attempts. */
    fake_state permanent = {.status_count = 0, .error_count = 1,
                            .error_errno = EACCES};
    resp = (aws_resp){0};
    rc = aws_http_execute(ctx, &req, &resp, fake_transport, &permanent);
    CHECK(rc == EACCES, "permanent transport error propagated");
    CHECK(permanent.calls == 1, "permanent errno is not retried");
    aws_resp_free(&resp);
    aws_free(ctx);
}

static void test_argument_validation(void)
{
    aws_ctx *ctx = make_ctx();
    aws_resp resp = {0};
    aws_req req = {.service = "ec2", .region = "us-east-1",
                   .method = "GET", .path = "/"};
    fake_state st = {0};
    CHECK(aws_http_execute(NULL, &req, &resp, fake_transport, &st) == EINVAL,
          "NULL ctx rejected");
    CHECK(aws_http_execute(ctx, NULL, &resp, fake_transport, &st) == EINVAL,
          "NULL request rejected");
    CHECK(aws_http_execute(ctx, &req, NULL, fake_transport, &st) == EINVAL,
          "NULL response rejected");
    CHECK(aws_http_execute(ctx, &req, &resp, NULL, &st) == EINVAL,
          "NULL transport rejected");
    aws_req missing = {.service = "ec2", .region = NULL};
    CHECK(aws_http_execute(ctx, &missing, &resp, fake_transport, &st) == EINVAL,
          "missing region rejected");
    aws_free(ctx);
}

int main(void)
{
    test_signed_request_headers();
    test_extra_signed_headers();
    test_invalid_extra_header_rejected();
    test_unsigned_payload_retry();
    test_no_retry_on_4xx();
    test_transport_error_retry_and_exhaustion();
    test_argument_validation();

    if (failures != 0) {
        fprintf(stderr, "%d retry check(s) failed\n", failures);
        return 1;
    }
    printf("retry_test: all checks passed\n");
    return 0;
}
