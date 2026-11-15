/*
 * ddns_test.c — seam-injected tests for core/ddns (spec §5.7).
 *
 * No sockets are opened: a fake ddns_http_ops implementation returns fixed
 * Namecheap XML bodies, so URL construction, percent-encoding, credential
 * redaction, <ErrCount>/<ErrN> parsing, and IP-echo parsing are pinned with
 * fixed vectors (CONTRACT Amendment 4).
 */

#include "ddns.h"
#include "ddns_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

typedef struct {
    int rc;
    long status;
    const char *body;
    size_t len;
    size_t calls;
    char url[1024];
} fake_http;

static fake_http public_fake;

static int fake_get(void *ud, const char *url, char *body, size_t cap,
                    size_t *len, long *status) {
    fake_http *fake = ud != NULL ? ud : &public_fake;

    fake->calls++;
    snprintf(fake->url, sizeof fake->url, "%s", url);
    if (fake->rc != 0) {
        return fake->rc;
    }
    if (fake->len >= cap) {
        return EOVERFLOW;
    }
    memcpy(body, fake->body, fake->len);
    body[fake->len] = '\0';
    *len = fake->len;
    *status = fake->status;
    return 0;
}

static const ddns_http_ops fake_ops = {
    .get = fake_get,
};

/*
 * Production defines this in ddns_curl.c. Tests link the curl-free ddns_core
 * target and substitute the fake seam so the public wrappers are exercised
 * without a libcurl/mbedTLS link (CONTRACT Amendment 4).
 */
const ddns_http_ops *ddns_curl_ops(void) {
    return &fake_ops;
}

static const char xml_success[] =
    "<?xml version=\"1.0\"?><interface-response><Command>SETDNSHOST</Command>"
    "<Language>eng</Language><ErrCount>0</ErrCount><errors/><Done>true</Done>"
    "</interface-response>";

static const char xml_failure[] =
    "<?xml version=\"1.0\"?><interface-response><ErrCount>2</ErrCount>"
    "<Err1>No Records updated. A record not Found</Err1>"
    "<Err2>Unspecified error</Err2></interface-response>";

static void test_build_url(void) {
    char url[1024];

    CHECK(ddns_build_update_url("box", "example.com", "p@ss w&rd",
                                "203.0.113.9", url, sizeof url) == 0,
          "build url rc");
    CHECK(strcmp(url,
                 DDNS_UPDATE_BASE
                 "?host=box&domain=example.com&password=p%40ss%20w%26rd"
                 "&ip=203.0.113.9") == 0,
          "build url exact");

    CHECK(ddns_build_update_url("A.b-c_d~e", "example.com", "-._~",
                                "1.2.3.4", url, sizeof url) == 0,
          "unreserved rc");
    CHECK(strstr(url, "host=A.b-c_d~e") != NULL, "unreserved preserved");
    CHECK(strstr(url, "password=-._~") != NULL, "unreserved password");

    CHECK(ddns_build_update_url(NULL, "example.com", "x", "1.2.3.4", url,
                                sizeof url) == EINVAL,
          "null host");
    CHECK(ddns_build_update_url("box", "", "x", "1.2.3.4", url,
                                sizeof url) == EINVAL,
          "empty domain");
    CHECK(ddns_build_update_url("box", "example.com", "x", "1.2.3.4", url, 8) ==
              ENAMETOOLONG,
          "short buffer");
}

static void test_redact(void) {
    char out[256];

    CHECK(ddns_redact_url(DDNS_UPDATE_BASE
                          "?host=box&domain=example.com&password=s3cr3t"
                          "&ip=203.0.113.9",
                          out, sizeof out) == 0,
          "redact rc");
    CHECK(strstr(out, "password=REDACTED&ip=203.0.113.9") != NULL,
          "redacted value");
    CHECK(strstr(out, "s3cr3t") == NULL, "secret removed");

    CHECK(ddns_redact_url("https://h/x?password=abc", out, sizeof out) == 0,
          "redact at end rc");
    CHECK(strcmp(out, "https://h/x?password=REDACTED") == 0,
          "redact at end value");

    CHECK(ddns_redact_url("https://h/x?ip=1.2.3.4", out, sizeof out) == 0,
          "no password rc");
    CHECK(strcmp(out, "https://h/x?ip=1.2.3.4") == 0, "no password unchanged");

    CHECK(ddns_redact_url(NULL, out, sizeof out) == EINVAL, "redact null");
}

static void test_parse_response(void) {
    bool updated = false;
    char error[128];

    memset(error, 0, sizeof error);
    CHECK(ddns_parse_response(xml_success, &updated, error, sizeof error) == 0,
          "success xml rc");
    CHECK(updated, "success updated");
    CHECK(error[0] == '\0', "success no error text");

    memset(error, 0, sizeof error);
    updated = true;
    CHECK(ddns_parse_response(xml_failure, &updated, error, sizeof error) == 0,
          "failure xml rc");
    CHECK(!updated, "failure updated false");
    CHECK(strstr(error, "No Records updated") != NULL, "failure error text");

    /* The tools/ddns parser strips NUL bytes before scanning. */
    char embedded_nul[] = "<ErrCount>0</ErrCount>\0<Done>true</Done>";
    updated = false;
    CHECK(ddns_parse_response(embedded_nul, &updated, error, sizeof error) == 0,
          "nul-stripped rc");
    CHECK(updated, "nul-stripped updated");

    char whitespace[] = "<ErrCount> 0 </ErrCount>";
    updated = false;
    CHECK(ddns_parse_response(whitespace, &updated, error, sizeof error) == 0,
          "whitespace rc");
    CHECK(updated, "whitespace updated");

    updated = true;
    CHECK(ddns_parse_response("<Done>true</Done>", &updated, error,
                              sizeof error) == EINVAL,
          "missing errcount");
    CHECK(ddns_parse_response("<ErrCount>oops</ErrCount>", &updated, error,
                              sizeof error) == EINVAL,
          "non-numeric errcount");
    CHECK(ddns_parse_response(NULL, &updated, error, sizeof error) == EINVAL,
          "null body");
}

static void test_update_success(void) {
    fake_http fake = {0};
    char ip[64] = "";
    bool updated = false;

    fake.body = xml_success;
    fake.len = sizeof xml_success - 1;
    fake.status = 200;

    CHECK(ddns_update_with(&fake_ops, &fake, "box", "example.com", "s3cr3t",
                           "203.0.113.9", &updated) == 0,
          "update rc");
    CHECK(updated, "update updated");
    CHECK(fake.calls == 1, "one request");
    CHECK(strstr(fake.url, "host=box&domain=example.com&") != NULL,
          "request host/domain");
    CHECK(strstr(fake.url, "password=s3cr3t") != NULL, "request password");
    CHECK(strstr(fake.url, "&ip=203.0.113.9") != NULL, "request ip");
    CHECK(ip[0] == '\0', "unused ip untouched");
}

static void test_update_endpoint_failure(void) {
    fake_http fake = {0};
    bool updated = true;

    fake.body = xml_failure;
    fake.len = sizeof xml_failure - 1;
    fake.status = 200;

    CHECK(ddns_update_with(&fake_ops, &fake, "box", "example.com", "s3cr3t",
                           "203.0.113.9", &updated) == EPROTO,
          "endpoint failure EPROTO");
    CHECK(!updated, "endpoint failure not updated");
}

static void test_update_transport_failure(void) {
    fake_http fake = {0};
    bool updated = true;

    fake.rc = EIO;
    CHECK(ddns_update_with(&fake_ops, &fake, "box", "example.com", "s3cr3t",
                           "203.0.113.9", &updated) == EIO,
          "transport error propagated");
    CHECK(!updated, "transport error not updated");
}

static void test_update_invalid(void) {
    fake_http fake = {0};
    bool updated = false;

    fake.body = xml_success;
    fake.len = sizeof xml_success - 1;
    CHECK(ddns_update_with(&fake_ops, &fake, "box", "example.com", "s3cr3t",
                           "not-an-ip", &updated) == EINVAL,
          "invalid ip");
    CHECK(fake.calls == 0, "no request for invalid ip");
    CHECK(ddns_update_with(&fake_ops, &fake, NULL, "example.com", "x",
                           "203.0.113.9", &updated) == EINVAL,
          "null host");
    CHECK(ddns_update_with(NULL, &fake, "box", "example.com", "x",
                           "203.0.113.9", &updated) == EINVAL,
          "null ops");
    CHECK(ddns_update_with(&fake_ops, &fake, "box", "example.com", "x",
                           "203.0.113.9", NULL) == EINVAL,
          "null updated");
}

static void test_ip_echo(void) {
    fake_http fake = {0};
    char ip[64] = "";

    fake.body = "203.0.113.7\r\n";
    fake.len = strlen(fake.body);
    fake.status = 200;
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "https://checkip.example/",
                            ip) == 0,
          "echo rc");
    CHECK(strcmp(ip, "203.0.113.7") == 0, "echo ip");
    CHECK(fake.calls == 1, "echo one request");

    char nul_body[] = "203.0.113.8\n\0trailing";
    fake = (fake_http){0};
    fake.body = nul_body;
    fake.len = sizeof nul_body - 1;
    fake.status = 200;
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "https://checkip.example/",
                            ip) == 0,
          "echo nul rc");
    CHECK(strcmp(ip, "203.0.113.8") == 0, "echo nul ip");

    fake = (fake_http){0};
    fake.body = "not an ip";
    fake.len = strlen(fake.body);
    fake.status = 200;
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "https://checkip.example/",
                            ip) != 0,
          "echo garbage rejected");

    fake = (fake_http){0};
    fake.body = "203.0.113.7";
    fake.len = strlen(fake.body);
    fake.status = 500;
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "https://checkip.example/",
                            ip) != 0,
          "echo http error rejected");

    fake = (fake_http){0};
    fake.rc = ETIMEDOUT;
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "https://checkip.example/",
                            ip) == ETIMEDOUT,
          "echo transport error");

    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "ftp://checkip.example/", ip) ==
              EINVAL,
          "echo bad scheme");
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, NULL, ip) == EINVAL,
          "echo null url");
    CHECK(ddns_ip_echo_with(&fake_ops, &fake, "https://checkip.example/",
                            NULL) == EINVAL,
          "echo null out");
}

static void test_parse_echo(void) {
    char ip[64] = "";

    CHECK(ddns_parse_echo_ip(" 203.0.113.6 \n", ip) == 0, "parse echo rc");
    CHECK(strcmp(ip, "203.0.113.6") == 0, "parse echo value");
    CHECK(ddns_parse_echo_ip("", ip) == EINVAL, "parse echo empty");
    CHECK(ddns_parse_echo_ip("1.2.3", ip) == EINVAL, "parse echo short");
    CHECK(ddns_parse_echo_ip(NULL, ip) == EINVAL, "parse echo null");
}

static void test_public_wrappers(void) {
    bool updated = false;
    char ip[64] = "";

    public_fake = (fake_http){0};
    public_fake.body = xml_success;
    public_fake.len = sizeof xml_success - 1;
    public_fake.status = 200;
    CHECK(ddns_update("box", "example.com", "s3cr3t", "203.0.113.9",
                      &updated) == 0,
          "public update rc");
    CHECK(updated, "public update updated");

    public_fake = (fake_http){0};
    public_fake.body = "203.0.113.4\n";
    public_fake.len = strlen(public_fake.body);
    public_fake.status = 200;
    CHECK(ddns_ip_echo("https://checkip.example/", ip) == 0,
          "public echo rc");
    CHECK(strcmp(ip, "203.0.113.4") == 0, "public echo ip");
}

static void test_public_invalid(void) {
    char ip[64] = "";
    bool updated = false;

    CHECK(ddns_update(NULL, "example.com", "x", "203.0.113.9", &updated) ==
              EINVAL,
          "public update null host");
    CHECK(ddns_ip_echo(NULL, ip) == EINVAL, "public echo null url");
}

int main(void) {
    test_build_url();
    test_redact();
    test_parse_response();
    test_update_success();
    test_update_endpoint_failure();
    test_update_transport_failure();
    test_update_invalid();
    test_ip_echo();
    test_parse_echo();
    test_public_wrappers();
    test_public_invalid();

    if (failures != 0) {
        fprintf(stderr, "%d ddns check(s) failed\n", failures);
        return 1;
    }
    puts("ddns_test: all checks passed");
    return 0;
}
