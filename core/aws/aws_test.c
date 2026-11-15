/*
 * aws_test.c — unit tests for the non-network core/aws surface:
 * credential resolution + env stripping, endpoint/URL construction, retry
 * policy, sleep-free waiter semantics, response helpers, error-code extraction
 * and clock-skew diagnosis.
 */

#include "aws.h"
#include "aws_internal.h"
#include "../ini/ini.h"
#include "yyjson.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void write_credentials(const char *home)
{
    char path[512];
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.aws", home);
    mkdir(dir, 0700);
    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror("fopen credentials");
        exit(2);
    }
    fputs("[default]\n"
          "aws_access_key_id = AKIADEFAULT\n"
          "aws_secret_access_key = secret-default\n"
          "\n"
          "[proj]\n"
          "aws_access_key_id = AKIAPROJ\n"
          "aws_secret_access_key = secret-proj\n"
          "aws_session_token = token-proj\n",
          f);
    fclose(f);
}

/* Build a temp HOME with a credentials file; returns malloc'd path. */
static char *make_home(void)
{
    char *home = strdup("/tmp/stackctl-aws-XXXXXX");
    if (home == NULL || mkdtemp(home) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    write_credentials(home);
    return home;
}

static void test_init_and_env_stripping(void)
{
    char *home = make_home();
    setenv("HOME", home, 1);
    setenv("AWS_PROFILE", "ambient", 1);
    setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT", 1);
    setenv("AWS_SESSION_TOKEN", "ambient-token", 1);
    setenv("STACKCTL_ENDPOINT_URL", "http://127.0.0.1:9", 1);

    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == 0, "aws_init(proj) succeeds");
    CHECK(ctx != NULL, "aws_init returns a context");
    CHECK(getenv("AWS_PROFILE") == NULL, "AWS_PROFILE stripped");
    CHECK(getenv("AWS_ACCESS_KEY_ID") == NULL, "AWS_ACCESS_KEY_ID stripped");
    CHECK(getenv("AWS_SESSION_TOKEN") == NULL, "AWS_SESSION_TOKEN stripped");
    CHECK(getenv("STACKCTL_ENDPOINT_URL") != NULL,
          "STACKCTL_ENDPOINT_URL preserved");

    aws_ctx *missing = NULL;
    CHECK(aws_init(&missing, "absent-profile") != 0, "missing profile rejected");
    CHECK(missing == NULL, "missing profile leaves out-param NULL");
    CHECK(aws_init(NULL, "proj") != 0, "NULL out rejected");

    aws_free(ctx);
    aws_free(NULL); /* must not crash */

    unsetenv("STACKCTL_ENDPOINT_URL");
    free(home);
}

/* Credential-load failure must NOT leave ambient AWS_* exports behind. */
static void test_env_stripped_even_on_failure(void)
{
    char *home = make_home();
    setenv("HOME", home, 1);
    setenv("AWS_PROFILE", "ambient", 1);
    setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret", 1);
    setenv("AWS_SESSION_TOKEN", "ambient-token", 1);

    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "absent-profile") == ENOENT, "missing profile fails");
    CHECK(ctx == NULL, "no context on failure");
    CHECK(getenv("AWS_PROFILE") == NULL, "AWS_PROFILE stripped on failure");
    CHECK(getenv("AWS_ACCESS_KEY_ID") == NULL,
          "AWS_ACCESS_KEY_ID stripped on failure");
    CHECK(getenv("AWS_SECRET_ACCESS_KEY") == NULL,
          "AWS_SECRET_ACCESS_KEY stripped on failure");
    CHECK(getenv("AWS_SESSION_TOKEN") == NULL,
          "AWS_SESSION_TOKEN stripped on failure");

    /* Also strip when HOME itself is unavailable (no file to read). */
    setenv("AWS_ACCESS_KEY_ID", "AKIAAMBIENT", 1);
    unsetenv("HOME");
    CHECK(aws_init(&ctx, "proj") == ENOENT, "missing HOME fails");
    CHECK(getenv("AWS_ACCESS_KEY_ID") == NULL,
          "AWS_ACCESS_KEY_ID stripped when HOME unset");

    free(home);
}

/* The credentials adapter must agree with core/ini's section/key writer. */
static void test_adapter_reads_ini_written_file(void)
{
    char *home = strdup("/tmp/stackctl-aws-ini-XXXXXX");
    CHECK(home != NULL && mkdtemp(home) != NULL, "temp home created");
    if (home == NULL || home[0] == '\0') {
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.aws", home);
    CHECK(mkdir(dir, 0700) == 0, "credentials dir created");

    CHECK(ini_upsert_section(path, "default", "aws_access_key_id",
                             "AKIADEFAULT", NULL) == 0,
          "ini writes default access key");
    CHECK(ini_upsert_section(path, "default", "aws_secret_access_key",
                             "secret-default", NULL) == 0,
          "ini writes default secret");
    CHECK(ini_upsert_section(path, "proj", "aws_access_key_id", "AKIAPROJ",
                             NULL) == 0,
          "ini writes proj access key");
    CHECK(ini_upsert_section(path, "proj", "aws_secret_access_key",
                             "secret-proj", NULL) == 0,
          "ini writes proj secret");

    setenv("HOME", home, 1);
    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == 0,
          "aws_init reads a file written by core/ini");
    if (ctx != NULL) {
        CHECK(ctx->access_key != NULL &&
                  strcmp(ctx->access_key, "AKIAPROJ") == 0,
              "adapter accepted ini-written access key");
        CHECK(ctx->secret_key != NULL &&
                  strcmp(ctx->secret_key, "secret-proj") == 0,
              "adapter accepted ini-written secret");
        aws_free(ctx);
    }

    free(home);
}

/* Oversized credentials files are rejected, never silently truncated. */
static void test_credentials_size_limit(void)
{
    char *home = strdup("/tmp/stackctl-aws-big-XXXXXX");
    CHECK(home != NULL && mkdtemp(home) != NULL, "temp home created");
    if (home == NULL || home[0] == '\0') {
        return;
    }
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.aws", home);
    mkdir(dir, 0700);
    char path[512];
    snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL, "oversized credentials opened");
    if (f != NULL) {
        fputs("[proj]\naws_access_key_id = AKIAPROJ\n"
              "aws_secret_access_key = secret-proj\n",
              f);
        char filler[4096];
        memset(filler, 'x', sizeof(filler) - 1);
        filler[sizeof(filler) - 1] = '\n';
        for (int i = 0; i < 80; i++) { /* ~320 KiB */
            fwrite(filler, 1, sizeof(filler) - 1, f);
        }
        fclose(f);
    }

    setenv("HOME", home, 1);
    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == EFBIG,
          "credentials file over the size cap is rejected");
    CHECK(ctx == NULL, "no context for oversized credentials");
    free(home);
}

static void test_build_url_default_endpoint(void)
{
    char *home = make_home();
    setenv("HOME", home, 1);
    unsetenv("STACKCTL_ENDPOINT_URL");

    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "default") == 0, "aws_init(default)");

    char *url = NULL;
    char *host = NULL;
    aws_req req = {
        .service = "ec2",
        .region = "us-east-1",
        .method = "GET",
        .path = "/",
        .query = "Action=DescribeInstances&Version=2016-11-15",
    };
    CHECK(aws_build_url(ctx, &req, &url, &host) == 0, "build_url ec2");
    CHECK(url != NULL && strcmp(url,
        "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15") == 0,
        "ec2 URL uses regional endpoint and query");
    CHECK(host != NULL && strcmp(host, "ec2.us-east-1.amazonaws.com") == 0,
        "ec2 host header");
    free(url);
    free(host);

    aws_req s3 = {
        .service = "s3",
        .region = "us-west-2",
        .method = "PUT",
        .path = "/my-bucket/releases/app.tar.gz",
    };
    url = NULL;
    host = NULL;
    CHECK(aws_build_url(ctx, &s3, &url, &host) == 0, "build_url s3");
    CHECK(url != NULL && strcmp(url,
        "https://s3.us-west-2.amazonaws.com/my-bucket/releases/app.tar.gz") == 0,
        "s3 path-style URL");
    CHECK(host != NULL && strcmp(host, "s3.us-west-2.amazonaws.com") == 0,
        "s3 host header");
    free(url);
    free(host);

    aws_req bad = {.service = "ec2", .region = NULL, .method = "GET", .path = "/"};
    CHECK(aws_build_url(ctx, &bad, &url, &host) != 0, "missing region rejected");

    aws_free(ctx);
    free(home);
}

static void test_build_url_endpoint_override(void)
{
    char *home = make_home();
    setenv("HOME", home, 1);
    setenv("STACKCTL_ENDPOINT_URL", "http://127.0.0.1:4567/base/", 1);

    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "default") == 0, "aws_init with override");

    aws_req req = {
        .service = "s3",
        .region = "us-east-1",
        .method = "GET",
        .path = "/b/k",
        .query = "x=1",
    };
    char *url = NULL;
    char *host = NULL;
    CHECK(aws_build_url(ctx, &req, &url, &host) == 0, "build_url override");
    CHECK(url != NULL && strcmp(url, "http://127.0.0.1:4567/base/b/k?x=1") == 0,
        "override base path, request path and query combine");
    CHECK(host != NULL && strcmp(host, "127.0.0.1:4567") == 0,
        "override host includes non-default port");
    free(url);
    free(host);

    aws_free(ctx);
    unsetenv("STACKCTL_ENDPOINT_URL");
    free(home);
}

static void test_retry_policy_and_backoff(void)
{
    CHECK(aws_should_retry(500), "500 retried");
    CHECK(aws_should_retry(502), "502 retried");
    CHECK(aws_should_retry(503), "503 retried");
    CHECK(aws_should_retry(504), "504 retried");
    CHECK(aws_should_retry(429), "429 retried");
    CHECK(!aws_should_retry(200), "200 not retried");
    CHECK(!aws_should_retry(400), "400 not retried");
    CHECK(!aws_should_retry(403), "403 not retried");
    CHECK(!aws_should_retry(404), "404 not retried");

    CHECK(aws_backoff_ms(0, 0) == 0, "zero base sleeps nothing");
    unsigned b0 = aws_backoff_ms(200, 0);
    unsigned b1 = aws_backoff_ms(200, 1);
    unsigned b2 = aws_backoff_ms(200, 2);
    CHECK(b0 >= 200 && b0 < 400, "first backoff in [base, 2*base)");
    CHECK(b1 >= 400 && b1 < 800, "second backoff doubles");
    CHECK(b2 >= 800 && b2 < 1600, "third backoff quadruples");
}

typedef struct {
    int calls;
    int succeed_at;
} wait_state;

static int wait_cb(aws_ctx *ctx, void *ud, int *done)
{
    (void)ctx;
    wait_state *st = ud;
    st->calls++;
    if (st->calls >= st->succeed_at) {
        *done = 1;
    }
    return 0;
}

static int wait_fail_cb(aws_ctx *ctx, void *ud, int *done)
{
    (void)ctx;
    (void)ud;
    (void)done;
    return EIO;
}

static void test_wait(void)
{
    wait_state st = {0, 3};
    int timed_out = -1;
    CHECK(aws_wait(NULL, wait_cb, &st, 5, 0, &timed_out) == 0, "waiter succeeds");
    CHECK(st.calls == 3, "waiter polls until done");
    CHECK(timed_out == 0, "waiter not timed out on success");

    wait_state never = {0, 99};
    timed_out = -1;
    CHECK(aws_wait(NULL, wait_cb, &never, 4, 0, &timed_out) == 0,
          "exhausted waiter returns 0");
    CHECK(never.calls == 4, "waiter polls exactly attempts times");
    CHECK(timed_out == 1, "exhausted waiter sets timed_out");

    timed_out = -1;
    CHECK(aws_wait(NULL, wait_fail_cb, NULL, 4, 0, &timed_out) == EIO,
          "waiter propagates callback error");

    CHECK(aws_wait(NULL, wait_cb, &st, 0, 0, &timed_out) == EINVAL,
          "attempts < 1 rejected");
}

static void add_header(aws_resp *resp, const char *name, const char *value)
{
    aws_header *grown = realloc(resp->headers,
                                (resp->header_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        exit(2);
    }
    resp->headers = grown;
    resp->headers[resp->header_count].name = strdup(name);
    resp->headers[resp->header_count].value = strdup(value);
    resp->header_count++;
}

static void test_response_helpers(void)
{
    aws_resp resp = {0};
    resp.status = 200;
    add_header(&resp, "Content-Type", "application/json");
    add_header(&resp, "X-Amz-Request-Id", "abc123");
    resp.body = strdup("{\"ok\":true,\"n\":7}");
    resp.body_len = strlen(resp.body);

    CHECK(strcmp(aws_resp_header(&resp, "content-type"), "application/json") == 0,
          "header lookup is case-insensitive");
    CHECK(strcmp(aws_resp_header(&resp, "X-AMZ-REQUEST-ID"), "abc123") == 0,
          "header lookup uppercase");
    CHECK(aws_resp_header(&resp, "absent") == NULL, "absent header is NULL");

    yyjson_doc *doc = aws_resp_json(&resp);
    CHECK(doc != NULL, "body parsed as JSON");
    if (doc != NULL) {
        yyjson_val *root = yyjson_doc_get_root(doc);
        CHECK(yyjson_get_bool(yyjson_obj_get(root, "ok")), "JSON ok=true");
        CHECK(yyjson_get_int(yyjson_obj_get(root, "n")) == 7, "JSON n=7");
    }
    CHECK(aws_resp_json(&resp) == doc, "JSON parse cached on the response");
    aws_resp_free(&resp);
    CHECK(resp.headers == NULL && resp.body == NULL && resp.json == NULL,
          "aws_resp_free zeroes owned fields");
}

static void test_error_code(void)
{
    char code[AWS_ERROR_CODE_LEN];

    aws_resp json_resp = {0};
    json_resp.status = 404;
    json_resp.body = strdup("{\"__type\":\"com.amazonaws.s3#NoSuchKey\","
                            "\"message\":\"missing\"}");
    json_resp.body_len = strlen(json_resp.body);
    CHECK(aws_error_code(&json_resp, code) == 1, "JSON error code found");
    CHECK(strcmp(code, "NoSuchKey") == 0, "JSON __type namespace stripped");
    aws_resp_free(&json_resp);

    aws_resp xml_resp = {0};
    xml_resp.status = 403;
    xml_resp.body = strdup("<Error><Code>AccessDenied</Code></Error>");
    xml_resp.body_len = strlen(xml_resp.body);
    CHECK(aws_error_code(&xml_resp, code) == 1, "XML error code found");
    CHECK(strcmp(code, "AccessDenied") == 0, "XML <Code> extracted");
    aws_resp_free(&xml_resp);

    aws_resp plain = {0};
    plain.status = 200;
    plain.body = strdup("{\"ok\":true}");
    plain.body_len = strlen(plain.body);
    CHECK(aws_error_code(&plain, code) == 0, "no error code on success body");
    aws_resp_free(&plain);
}

static void http_date_now_minus(long seconds, char out[64])
{
    time_t when = time(NULL) - seconds;
    struct tm tm;
    gmtime_r(&when, &tm);
    strftime(out, 64, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

static void test_clock_skew(void)
{
    char date[64];
    http_date_now_minus(3600, date);

    aws_resp skew = {0};
    skew.status = 403;
    add_header(&skew, "Date", date);
    skew.body = strdup("{\"__type\":\"RequestTimeTooSkewed\","
                       "\"message\":\"clock\"}");
    skew.body_len = strlen(skew.body);
    long delta = 0;
    CHECK(aws_clock_skew(&skew, &delta) == 1, "skew-class 403 detected");
    CHECK(delta > 3590 && delta < 3610, "local-minus-server delta ~3600s");
    aws_resp_free(&skew);

    aws_resp denied = {0};
    denied.status = 403;
    add_header(&denied, "Date", date);
    denied.body = strdup("{\"__type\":\"AccessDenied\"}");
    denied.body_len = strlen(denied.body);
    delta = 42;
    CHECK(aws_clock_skew(&denied, &delta) == 0, "non-skew 403 not flagged");
    aws_resp_free(&denied);

    /* Wrong secret / signing failure is an auth error, never clock skew. */
    aws_resp bad_sig = {0};
    bad_sig.status = 403;
    add_header(&bad_sig, "Date", date);
    bad_sig.body = strdup("{\"__type\":\"InvalidSignatureException\","
                          "\"message\":\"signature mismatch\"}");
    bad_sig.body_len = strlen(bad_sig.body);
    delta = 42;
    CHECK(aws_clock_skew(&bad_sig, &delta) == 0,
          "InvalidSignatureException is an auth error, not clock skew");
    aws_resp_free(&bad_sig);

    aws_resp ok = {0};
    ok.status = 200;
    add_header(&ok, "Date", date);
    CHECK(aws_clock_skew(&ok, &delta) == 0, "200 not flagged");
    aws_resp_free(&ok);

    CHECK(aws_clock_skew(NULL, &delta) == -EINVAL, "NULL response rejected");
}

int main(void)
{
    test_init_and_env_stripping();
    test_env_stripped_even_on_failure();
    test_adapter_reads_ini_written_file();
    test_credentials_size_limit();
    test_build_url_default_endpoint();
    test_build_url_endpoint_override();
    test_retry_policy_and_backoff();
    test_wait();
    test_response_helpers();
    test_error_code();
    test_clock_skew();

    if (failures != 0) {
        fprintf(stderr, "%d aws unit check(s) failed\n", failures);
        return 1;
    }
    printf("aws_test: all checks passed\n");
    return 0;
}
