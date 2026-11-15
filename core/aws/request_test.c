/*
 * request_test.c — transport seam integration tests for aws_request().
 *
 * A forked local HTTP server binds 127.0.0.1:0 and serves fixture responses;
 * the client is pointed at it through STACKCTL_ENDPOINT_URL. Covers: SigV4
 * Authorization + host headers, query propagation, response header/body/JSON
 * surfacing, UNSIGNED-PAYLOAD for S3, retry on 503 -> 200, and no-retry on 400.
 */

#include "aws.h"
#include "aws_internal.h"
#include "yyjson.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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
    int response_count;
    int statuses[8];
    const char *body;
    const char *extra_header;   /* "Name: value" line, or NULL */
    int method_must_be_get;
    int unsigned_payload;
} server_spec;

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
    fputs("[proj]\n"
          "aws_access_key_id = AKIAPROJ\n"
          "aws_secret_access_key = secret-proj\n"
          "aws_session_token = token-proj\n",
          f);
    fclose(f);
}

static char *make_home(void)
{
    char *home = strdup("/tmp/stackctl-aws-req-XXXXXX");
    if (home == NULL || mkdtemp(home) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    write_credentials(home);
    return home;
}

static const char *ci_strstr(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p != '\0'; p++) {
        size_t i = 0;
        while (i < nlen && p[i] != '\0') {
            char a = p[i];
            char b = needle[i];
            if (a >= 'A' && a <= 'Z') {
                a = (char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char)(b - 'A' + 'a');
            }
            if (a != b) {
                break;
            }
            i++;
        }
        if (i == nlen) {
            return p;
        }
    }
    return NULL;
}

static size_t read_headers(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t got = recv(fd, buf + n, cap - 1 - n, 0);
        if (got <= 0) {
            break;
        }
        n += (size_t)got;
        buf[n] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL) {
            break;
        }
    }
    return n;
}

static void serve(int listen_fd, const server_spec *spec)
{
    for (int i = 0; i < spec->response_count; i++) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            _exit(4);
        }
        char request[8192];
        read_headers(fd, request, sizeof(request));

        if (spec->method_must_be_get && strncmp(request, "GET ", 4) != 0) {
            _exit(5);
        }
        if (ci_strstr(request, "authorization: aws4-hmac-sha256") == NULL ||
            ci_strstr(request, "credential=akiaproj/") == NULL) {
            _exit(6);
        }
        if (ci_strstr(request, "x-amz-date:") == NULL) {
            _exit(7);
        }
        if (ci_strstr(request, "x-amz-security-token: token-proj") == NULL) {
            _exit(8);
        }
        if (spec->unsigned_payload) {
            if (ci_strstr(request,
                         "x-amz-content-sha256: unsigned-payload") == NULL) {
                _exit(9);
            }
        }

        char head[512];
        int head_len = snprintf(head, sizeof(head),
                                "HTTP/1.1 %d Fixture\r\n"
                                "Content-Length: %zu\r\n"
                                "Content-Type: application/json\r\n"
                                "%s%s"
                                "Connection: close\r\n"
                                "\r\n",
                                spec->statuses[i],
                                strlen(spec->body),
                                spec->extra_header != NULL ? spec->extra_header : "",
                                spec->extra_header != NULL ? "\r\n" : "");
        if (head_len > 0) {
            (void)!write(fd, head, (size_t)head_len);
            (void)!write(fd, spec->body, strlen(spec->body));
        }
        close(fd);
    }
    close(listen_fd);
    _exit(0);
}

static pid_t start_server(const server_spec *spec, int *port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(2);
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 8) != 0) {
        perror("bind/listen");
        exit(2);
    }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        perror("getsockname");
        exit(2);
    }
    *port_out = ntohs(addr.sin_port);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        serve(fd, spec);
    }
    close(fd);
    return pid;
}

static void finish_server(pid_t pid)
{
    int status = 0;
    pid_t got = 0;
    /* Bounded wait so a broken client cannot hang the test on accept(). */
    for (int i = 0; i < 300; i++) {
        got = waitpid(pid, &status, WNOHANG);
        if (got == pid) {
            break;
        }
        usleep(10000);
    }
    if (got != pid) {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        CHECK(0, "mock server finished serving its fixtures");
        return;
    }
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "mock server request assertions passed");
}

static void set_endpoint(int port)
{
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d", port);
    setenv("STACKCTL_ENDPOINT_URL", url, 1);
}

static void test_signed_request_roundtrip(void)
{
    server_spec spec = {
        .response_count = 1,
        .statuses = {200},
        .body = "{\"ok\":true}",
        .extra_header = "X-Test: yes",
        .method_must_be_get = 1,
        .unsigned_payload = 0,
    };
    int port = 0;
    pid_t pid = start_server(&spec, &port);
    set_endpoint(port);

    char *home = make_home();
    setenv("HOME", home, 1);
    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == 0, "aws_init(proj)");
    aws_test_set_backoff(ctx, 0);

    aws_resp resp = {0};
    aws_req req = {
        .service = "ec2",
        .region = "us-east-1",
        .method = "GET",
        .path = "/",
        .query = "Action=DescribeInstances&Version=2016-11-15",
    };
    int rc = aws_request(ctx, &req, &resp);
    finish_server(pid);

    CHECK(rc == 0, "aws_request returns 0 on an HTTP response");
    CHECK(resp.status == 200, "status 200 surfaced");
    CHECK(resp.body != NULL && strcmp(resp.body, "{\"ok\":true}") == 0,
          "body surfaced");
    CHECK(resp.body_len == strlen("{\"ok\":true}"), "body length surfaced");
    const char *test_header = aws_resp_header(&resp, "x-test");
    CHECK(test_header != NULL && strcmp(test_header, "yes") == 0,
          "response header surfaced");

    yyjson_doc *doc = aws_resp_json(&resp);
    CHECK(doc != NULL && yyjson_is_true(
        yyjson_obj_get(yyjson_doc_get_root(doc), "ok")),
        "response JSON parsed on demand");

    aws_resp_free(&resp);
    aws_free(ctx);
    unsetenv("STACKCTL_ENDPOINT_URL");
    free(home);
}

static void test_unsigned_payload_and_retry(void)
{
    server_spec spec = {
        .response_count = 3,
        .statuses = {503, 503, 200},
        .body = "{\"done\":true}",
        .extra_header = NULL,
        .method_must_be_get = 1,
        .unsigned_payload = 1,
    };
    int port = 0;
    pid_t pid = start_server(&spec, &port);
    set_endpoint(port);

    char *home = make_home();
    setenv("HOME", home, 1);
    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == 0, "aws_init(proj) for retry");
    aws_test_set_backoff(ctx, 0);

    aws_resp resp = {0};
    aws_req req = {
        .service = "s3",
        .region = "us-east-1",
        .method = "GET",
        .path = "/bucket/key",
        .unsigned_payload = 1,
    };
    int rc = aws_request(ctx, &req, &resp);
    finish_server(pid);

    CHECK(rc == 0, "retried request returns 0");
    CHECK(resp.status == 200, "retry after two 503s reaches 200");
    yyjson_doc *doc = aws_resp_json(&resp);
    CHECK(doc != NULL && yyjson_is_true(
        yyjson_obj_get(yyjson_doc_get_root(doc), "done")),
        "final retried body parsed");

    aws_resp_free(&resp);
    aws_free(ctx);
    unsetenv("STACKCTL_ENDPOINT_URL");
    free(home);
}

static void test_no_retry_on_client_error(void)
{
    server_spec spec = {
        .response_count = 1,
        .statuses = {400},
        .body = "{\"__type\":\"InvalidParameterValue\"}",
        .extra_header = NULL,
        .method_must_be_get = 1,
        .unsigned_payload = 0,
    };
    int port = 0;
    pid_t pid = start_server(&spec, &port);
    set_endpoint(port);

    char *home = make_home();
    setenv("HOME", home, 1);
    aws_ctx *ctx = NULL;
    CHECK(aws_init(&ctx, "proj") == 0, "aws_init(proj) no-retry");
    aws_test_set_backoff(ctx, 0);

    aws_resp resp = {0};
    aws_req req = {
        .service = "ec2",
        .region = "us-east-1",
        .method = "GET",
        .path = "/",
    };
    int rc = aws_request(ctx, &req, &resp);
    finish_server(pid);

    CHECK(rc == 0, "4xx is returned to the caller, not a transport error");
    CHECK(resp.status == 400, "400 surfaced without retry");
    char code[AWS_ERROR_CODE_LEN];
    CHECK(aws_error_code(&resp, code) == 1 &&
          strcmp(code, "InvalidParameterValue") == 0,
          "4xx error code parsed");

    aws_resp_free(&resp);
    aws_free(ctx);
    unsetenv("STACKCTL_ENDPOINT_URL");
    free(home);
}

int main(void)
{
    test_signed_request_roundtrip();
    test_unsigned_payload_and_retry();
    test_no_retry_on_client_error();

    if (failures != 0) {
        fprintf(stderr, "%d request check(s) failed\n", failures);
        return 1;
    }
    printf("request_test: all checks passed\n");
    return 0;
}
