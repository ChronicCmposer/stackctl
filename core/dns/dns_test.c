/*
 * dns_test.c — seam-injected tests for core/dns (spec §5.7).
 *
 * No sockets are opened: a fake dns_ops implementation supplies the
 * authoritative-NS list and per-server A answers, so the iteration order,
 * parked detection, FQDN construction, and error propagation are all pinned
 * with fixed vectors (CONTRACT Amendment 4).
 */

#include "dns.h"
#include "dns_internal.h"
#include "dns_wire.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
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
    int list_rc;
    size_t nservers;
    char servers[4][DNS_MAX_SERVER];
    int query_rc[4];
    bool query_found[4];
    char query_ip[4][64];
    size_t query_calls;
    char seen_server[4][DNS_MAX_SERVER];
    char seen_fqdn[256];
} fake_dns;

static int fake_list(void *ud, const char *domain,
                     char (*servers)[DNS_MAX_SERVER], size_t max,
                     size_t *count) {
    fake_dns *fake = ud;

    *count = 0;
    if (fake->list_rc != 0) {
        return fake->list_rc;
    }
    if (strcmp(domain, "example.com") != 0) {
        return ENOENT;
    }
    for (size_t i = 0; i < fake->nservers && i < max; i++) {
        snprintf(servers[i], DNS_MAX_SERVER, "%s", fake->servers[i]);
        (*count)++;
    }
    return 0;
}

static int fake_query(void *ud, const char *server_ip, const char *fqdn,
                      char ip[64], bool *found) {
    fake_dns *fake = ud;
    size_t index = fake->query_calls;

    snprintf(fake->seen_fqdn, sizeof fake->seen_fqdn, "%s", fqdn);
    if (index < ARRAY_LEN(fake->seen_server)) {
        snprintf(fake->seen_server[index], DNS_MAX_SERVER, "%s", server_ip);
    }
    fake->query_calls++;
    if (index >= ARRAY_LEN(fake->query_rc)) {
        *found = false;
        return EIO;
    }
    *found = fake->query_found[index];
    if (*found) {
        snprintf(ip, 64, "%s", fake->query_ip[index]);
    }
    return fake->query_rc[index];
}

static void fake_reset(fake_dns *fake) {
    memset(fake, 0, sizeof *fake);
}

static const dns_ops fake_ops = {
    .list_servers = fake_list,
    .query_a = fake_query,
};

/*
 * Production seam for the public wrappers: dns.c calls dns_cares_ops(), which
 * :dns supplies in production and this test binary supplies here. That keeps
 * dns_a_record()/dns_record_exists() exercised hermetically end-to-end.
 */
static fake_dns public_fake;

static int public_list(void *ud, const char *domain,
                       char (*servers)[DNS_MAX_SERVER], size_t max,
                       size_t *count) {
    (void)ud;
    return fake_list(&public_fake, domain, servers, max, count);
}

static int public_query(void *ud, const char *server_ip, const char *fqdn,
                        char ip[64], bool *found) {
    (void)ud;
    return fake_query(&public_fake, server_ip, fqdn, ip, found);
}

static const dns_ops public_ops = {
    .list_servers = public_list,
    .query_a = public_query,
};

const dns_ops *dns_cares_ops(void) {
    return &public_ops;
}

static void test_build_fqdn(void) {
    struct {
        const char *host;
        const char *domain;
        const char *expected;
        int rc;
    } cases[] = {
        {"box", "example.com", "box.example.com", 0},
        {"@", "example.com", "example.com", 0},
        {"", "example.com", "example.com", 0},
        {"box.example.com", "example.com", "box.example.com", 0},
        {"box.example.com.", "example.com.", "box.example.com", 0},
        {"BOX", "Example.COM", "BOX.Example.COM", 0},
        {"box", "bad domain.com", NULL, EINVAL},
        {"", "", NULL, EINVAL},
    };
    char out[DNS_MAX_FQDN + 1];

    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        memset(out, 0, sizeof out);
        int rc = dns_build_fqdn(cases[i].host, cases[i].domain, out,
                                sizeof out);

        CHECK(rc == cases[i].rc, cases[i].expected == NULL ? "bad-input rc"
                                                           : "fqdn rc");
        if (rc == 0) {
            CHECK(strcmp(out, cases[i].expected) == 0, "fqdn value");
        }
    }

    char too_long[300];

    memset(too_long, 'a', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = '\0';
    CHECK(dns_build_fqdn(too_long, "example.com", out, sizeof out) ==
              ENAMETOOLONG,
          "fqdn too long");
    CHECK(dns_build_fqdn("box", "example.com", out, 4) == ENAMETOOLONG,
          "fqdn buffer too small");
    CHECK(dns_build_fqdn(NULL, "example.com", out, sizeof out) == EINVAL,
          "fqdn null host");
}

static void test_parked(void) {
    CHECK(dns_ip_is_parked("0.0.0.0"), "0.0.0.0 parked");
    CHECK(dns_ip_is_parked("127.0.0.1"), "127.0.0.1 parked");
    CHECK(!dns_ip_is_parked("127.0.0.2"), "127.0.0.2 not parked");
    CHECK(!dns_ip_is_parked("10.0.0.1"), "private not parked");
    CHECK(!dns_ip_is_parked("203.0.113.9"), "public not parked");
    CHECK(!dns_ip_is_parked(""), "empty not parked");
    CHECK(!dns_ip_is_parked(NULL), "null not parked");
    CHECK(!dns_ip_is_parked("not-an-ip"), "garbage not parked");
}

static void test_a_record_second_server(void) {
    fake_dns fake;
    char ip[64] = "";
    bool parked = true;

    fake_reset(&fake);
    fake.list_rc = 0;
    fake.nservers = 2;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    snprintf(fake.servers[1], DNS_MAX_SERVER, "%s", "192.0.2.2");
    fake.query_rc[0] = EIO;
    fake.query_found[0] = false;
    fake.query_rc[1] = 0;
    fake.query_found[1] = true;
    snprintf(fake.query_ip[1], 64, "%s", "203.0.113.9");

    int rc = dns_a_record_with(&fake_ops, &fake, "example.com", "box", ip,
                               &parked);

    CHECK(rc == 0, "second server success rc");
    CHECK(strcmp(ip, "203.0.113.9") == 0, "second server ip");
    CHECK(!parked, "second server not parked");
    CHECK(strcmp(fake.seen_fqdn, "box.example.com") == 0, "queried fqdn");
    CHECK(strcmp(fake.seen_server[0], "192.0.2.1") == 0, "first server tried");
    CHECK(strcmp(fake.seen_server[1], "192.0.2.2") == 0, "second server tried");
    CHECK(fake.query_calls == 2, "two queries");
}

static void test_a_record_parked(void) {
    fake_dns fake;
    char ip[64] = "";
    bool parked = false;

    fake_reset(&fake);
    fake.nservers = 1;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    fake.query_found[0] = true;
    snprintf(fake.query_ip[0], 64, "%s", "0.0.0.0");

    CHECK(dns_a_record_with(&fake_ops, &fake, "example.com", "@", ip,
                            &parked) == 0,
          "parked rc");
    CHECK(strcmp(ip, "0.0.0.0") == 0, "parked ip");
    CHECK(parked, "parked flag");
    CHECK(strcmp(fake.seen_fqdn, "example.com") == 0, "apex fqdn");
}

static void test_a_record_not_found(void) {
    fake_dns fake;
    char ip[64] = "unchanged";
    bool parked = true;

    fake_reset(&fake);
    fake.nservers = 1;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    fake.query_found[0] = false;

    int rc = dns_a_record_with(&fake_ops, &fake, "example.com", "box", ip,
                               &parked);

    CHECK(rc == ENOENT, "missing record ENOENT");
    CHECK(ip[0] == '\0', "ip cleared");
    CHECK(!parked, "not parked on missing");
}

static void test_a_record_all_errors(void) {
    fake_dns fake;
    char ip[64] = "";
    bool parked = false;

    fake_reset(&fake);
    fake.nservers = 2;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    snprintf(fake.servers[1], DNS_MAX_SERVER, "%s", "192.0.2.2");
    fake.query_rc[0] = EIO;
    fake.query_rc[1] = ETIMEDOUT;

    CHECK(dns_a_record_with(&fake_ops, &fake, "example.com", "box", ip,
                            &parked) == ETIMEDOUT,
          "last error propagated");
    CHECK(fake.query_calls == 2, "all servers tried");
}

static void test_a_record_no_servers(void) {
    fake_dns fake;
    char ip[64] = "";
    bool parked = false;

    fake_reset(&fake);
    fake.nservers = 0;
    CHECK(dns_a_record_with(&fake_ops, &fake, "example.com", "box", ip,
                            &parked) == ENOENT,
          "no authoritative servers");
}

static void test_a_record_list_error(void) {
    fake_dns fake;
    char ip[64] = "";
    bool parked = false;

    fake_reset(&fake);
    fake.list_rc = ETIMEDOUT;
    CHECK(dns_a_record_with(&fake_ops, &fake, "example.com", "box", ip,
                            &parked) == ETIMEDOUT,
          "list error propagated");
    CHECK(fake.query_calls == 0, "no query after list error");
}

static void test_record_exists(void) {
    fake_dns fake;
    bool exists = false;

    fake_reset(&fake);
    fake.nservers = 1;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    fake.query_found[0] = true;
    snprintf(fake.query_ip[0], 64, "%s", "203.0.113.5");
    CHECK(dns_record_exists_with(&fake_ops, &fake, "example.com", "box",
                                 &exists) == 0,
          "exists rc");
    CHECK(exists, "exists true");

    fake_reset(&fake);
    fake.nservers = 1;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    fake.query_found[0] = false;
    exists = true;
    CHECK(dns_record_exists_with(&fake_ops, &fake, "example.com", "box",
                                 &exists) == 0,
          "missing rc");
    CHECK(!exists, "exists false on missing");

    fake_reset(&fake);
    fake.list_rc = EIO;
    CHECK(dns_record_exists_with(&fake_ops, &fake, "example.com", "box",
                                 &exists) == EIO,
          "exists list error");
}

static void test_invalid_arguments(void) {
    fake_dns fake;
    char ip[64] = "";
    bool flag = false;

    fake_reset(&fake);
    CHECK(dns_a_record_with(NULL, NULL, "example.com", "box", ip, &flag) ==
              EINVAL,
          "null ops");
    CHECK(dns_a_record_with(&fake_ops, NULL, NULL, "box", ip, &flag) == EINVAL,
          "null domain");
    CHECK(dns_a_record_with(&fake_ops, NULL, "example.com", NULL, ip, &flag) ==
              EINVAL,
          "null host");
    CHECK(dns_a_record_with(&fake_ops, NULL, "example.com", "box", NULL,
                            &flag) == EINVAL,
          "null ip");
    CHECK(dns_a_record_with(&fake_ops, NULL, "example.com", "box", ip, NULL) ==
              EINVAL,
          "null parked");
    CHECK(dns_record_exists_with(&fake_ops, NULL, "example.com", "box", NULL) ==
              EINVAL,
          "null exists");

    /* The public wrappers validate before touching the network seam. */
    CHECK(dns_a_record(NULL, "box", ip, &flag) == EINVAL,
          "public null domain");
    CHECK(dns_record_exists("example.com", NULL, &flag) == EINVAL,
          "public null host");
}

/* --- synthetic DNS wire messages (no sockets) --------------------------- */

static size_t wire_put_name(unsigned char *buf, size_t pos, const char *name) {
    const char *label = name;

    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t length = dot != NULL ? (size_t)(dot - label) : strlen(label);

        buf[pos++] = (unsigned char)length;
        memcpy(buf + pos, label, length);
        pos += length;
        if (dot == NULL) {
            break;
        }
        label = dot + 1;
    }
    buf[pos++] = 0;
    return pos;
}

static size_t wire_put_header(unsigned char *buf, unsigned qd, unsigned an) {
    memset(buf, 0, 12);
    buf[0] = 0x12;
    buf[1] = 0x34;
    buf[2] = 0x81; /* QR | RD */
    buf[3] = 0x80; /* RA */
    buf[4] = (unsigned char)(qd >> 8);
    buf[5] = (unsigned char)qd;
    buf[6] = (unsigned char)(an >> 8);
    buf[7] = (unsigned char)an;
    return 12;
}

static size_t wire_put_question(unsigned char *buf, size_t pos,
                                const char *fqdn, unsigned type) {
    pos = wire_put_name(buf, pos, fqdn);
    buf[pos++] = (unsigned char)(type >> 8);
    buf[pos++] = (unsigned char)type;
    buf[pos++] = 0;
    buf[pos++] = 1; /* class IN */
    return pos;
}

static int wire_build_a_reply(unsigned char *buf, const char *fqdn,
                              const unsigned char addr[4], bool with_answer) {
    size_t pos = wire_put_header(buf, 1, with_answer ? 1u : 0u);

    pos = wire_put_question(buf, pos, fqdn, 1);
    if (with_answer) {
        buf[pos++] = 0xc0; /* compression pointer to the question name */
        buf[pos++] = 0x0c;
        buf[pos++] = 0;
        buf[pos++] = 1; /* type A */
        buf[pos++] = 0;
        buf[pos++] = 1; /* class IN */
        for (int i = 0; i < 4; i++) {
            buf[pos++] = 0; /* TTL */
        }
        buf[pos++] = 0;
        buf[pos++] = 4; /* RDLENGTH */
        memcpy(buf + pos, addr, 4);
        pos += 4;
    }
    return (int)pos;
}

static int wire_build_ns_reply(unsigned char *buf, const char *fqdn,
                               const char *const *ns, size_t count) {
    size_t pos = wire_put_header(buf, 1, (unsigned)count);

    pos = wire_put_question(buf, pos, fqdn, 2);
    for (size_t i = 0; i < count; i++) {
        buf[pos++] = 0xc0;
        buf[pos++] = 0x0c;
        buf[pos++] = 0;
        buf[pos++] = 2; /* type NS */
        buf[pos++] = 0;
        buf[pos++] = 1; /* class IN */
        for (int k = 0; k < 4; k++) {
            buf[pos++] = 0; /* TTL */
        }
        size_t rdlength_at = pos;
        pos += 2;
        size_t rdata_at = pos;

        pos = wire_put_name(buf, pos, ns[i]);
        size_t rdlength = pos - rdata_at;

        buf[rdlength_at] = (unsigned char)(rdlength >> 8);
        buf[rdlength_at + 1] = (unsigned char)rdlength;
    }
    return (int)pos;
}

static void test_wire_a_query(void) {
    unsigned char query[512];
    int len = 0;

    CHECK(dns_wire_build_a_query("box.example.com", query,
                                 (int)sizeof query, &len) == 0,
          "wire build rc");
    CHECK(len > 12, "wire build length");
    if (len > 12) {
        size_t tail = (size_t)len - 4;

        CHECK(query[tail] == 0 && query[tail + 1] == 1, "wire qtype A");
        CHECK(query[tail + 2] == 0 && query[tail + 3] == 1, "wire qclass IN");
    }

    unsigned char tiny[4];
    CHECK(dns_wire_build_a_query("box.example.com", tiny, (int)sizeof tiny,
                                 &len) == ENAMETOOLONG,
          "wire build too small");
    CHECK(dns_wire_build_a_query(NULL, query, (int)sizeof query, &len) ==
              EINVAL,
          "wire build null name");
}

static void test_wire_a_reply(void) {
    unsigned char reply[512];
    static const unsigned char addr[4] = {203, 0, 113, 7};
    char ip[64] = "";
    bool found = false;

    int len = wire_build_a_reply(reply, "box.example.com", addr, true);

    CHECK(dns_wire_parse_a_reply(reply, len, ip, &found) == 0,
          "wire parse A rc");
    CHECK(found, "wire parse A found");
    CHECK(strcmp(ip, "203.0.113.7") == 0, "wire parse A address");

    len = wire_build_a_reply(reply, "box.example.com", addr, false);
    ip[0] = '\0';
    found = true;
    CHECK(dns_wire_parse_a_reply(reply, len, ip, &found) == 0,
          "wire empty rc");
    CHECK(!found, "wire empty has no answer");
    CHECK(ip[0] == '\0', "wire empty clears ip");
}

static void test_wire_ns_reply(void) {
    unsigned char reply[512];
    const char *ns[] = {"ns1.example.net", "ns2.example.net"};
    char names[DNS_MAX_NS][DNS_NS_NAME_CAP];
    size_t count = 0;
    int len = wire_build_ns_reply(reply, "example.com", ns, 2);

    CHECK(dns_wire_parse_ns_reply(reply, len, names, DNS_MAX_NS, &count) == 0,
          "wire NS rc");
    CHECK(count == 2, "wire NS count");
    if (count == 2) {
        CHECK(strcmp(names[0], "ns1.example.net") == 0, "wire NS first");
        CHECK(strcmp(names[1], "ns2.example.net") == 0, "wire NS second");
    }
    for (size_t i = 0; i < count; i++) {
        CHECK(strcmp(names[i], "example.com") != 0,
              "wire NS excludes queried name");
    }
}

static void test_a_record_empty_answer(void) {
    fake_dns fake;
    char ip[64] = "stale";
    bool parked = true;

    fake_reset(&fake);
    fake.nservers = 1;
    snprintf(fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    fake.query_found[0] = true;
    fake.query_ip[0][0] = '\0';

    int rc = dns_a_record_with(&fake_ops, &fake, "example.com", "box", ip,
                               &parked);

    CHECK(rc != 0, "empty answer rejected");
    CHECK(ip[0] == '\0', "empty answer cleared ip");
    CHECK(!parked, "empty answer not parked");
}

static void test_public_wrappers(void) {
    char ip[64] = "";
    bool parked = true;
    bool exists = false;

    memset(&public_fake, 0, sizeof public_fake);
    public_fake.nservers = 1;
    snprintf(public_fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    public_fake.query_found[0] = true;
    snprintf(public_fake.query_ip[0], 64, "%s", "203.0.113.8");

    CHECK(dns_a_record("example.com", "box", ip, &parked) == 0,
          "public a_record rc");
    CHECK(strcmp(ip, "203.0.113.8") == 0, "public a_record ip");
    CHECK(!parked, "public a_record not parked");
    CHECK(strcmp(public_fake.seen_fqdn, "box.example.com") == 0,
          "public a_record fqdn");

    memset(&public_fake, 0, sizeof public_fake);
    public_fake.nservers = 1;
    snprintf(public_fake.servers[0], DNS_MAX_SERVER, "%s", "192.0.2.1");
    public_fake.query_found[0] = true;
    snprintf(public_fake.query_ip[0], 64, "%s", "203.0.113.8");

    CHECK(dns_record_exists("example.com", "box", &exists) == 0,
          "public record_exists rc");
    CHECK(exists, "public record_exists true");
}

int main(void) {
    test_build_fqdn();
    test_parked();
    test_a_record_second_server();
    test_a_record_parked();
    test_a_record_not_found();
    test_a_record_all_errors();
    test_a_record_no_servers();
    test_a_record_list_error();
    test_record_exists();
    test_invalid_arguments();
    test_wire_a_query();
    test_wire_a_reply();
    test_wire_ns_reply();
    test_a_record_empty_answer();
    test_public_wrappers();

    if (failures != 0) {
        fprintf(stderr, "%d dns check(s) failed\n", failures);
        return 1;
    }
    puts("dns_test: all checks passed");
    return 0;
}
