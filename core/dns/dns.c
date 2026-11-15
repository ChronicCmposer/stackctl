/*
 * dns.c — authoritative A-record reads for stackctl DDNS (spec §5.7).
 *
 * The network work lives behind the injectable dns_ops seam (dns_cares.c in
 * production); this file implements the protocol-independent behaviour:
 * FQDN construction, iteration across the authoritative NS set, parked-record
 * detection, and errno-style error propagation.
 */

#include "dns.h"
#include "dns_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define DNS_FQDN_LIMIT 253

static bool valid_name_chars(const char *name) {
    for (const unsigned char *p = (const unsigned char *)name; *p != '\0';
         p++) {
        if (!(isalnum(*p) || *p == '-' || *p == '.' || *p == '_')) {
            return false;
        }
    }
    return true;
}

static size_t strip_trailing_dots(const char *name) {
    size_t len = strlen(name);

    while (len > 0 && name[len - 1] == '.') {
        len--;
    }
    return len;
}

int dns_build_fqdn(const char *host, const char *domain, char *out,
                   size_t cap) {
    if (host == NULL || domain == NULL || out == NULL || cap == 0) {
        return EINVAL;
    }

    size_t dlen = strip_trailing_dots(domain);
    if (dlen == 0 || dlen > DNS_FQDN_LIMIT) {
        return EINVAL;
    }

    char dom[DNS_FQDN_LIMIT + 1];

    memcpy(dom, domain, dlen);
    dom[dlen] = '\0';
    if (!valid_name_chars(dom)) {
        return EINVAL;
    }

    size_t hlen = strip_trailing_dots(host);

    /* Apex: empty host or the conventional "@" placeholder. */
    if (hlen == 0 || (hlen == 1 && host[0] == '@')) {
        if (dlen + 1 > cap) {
            return ENAMETOOLONG;
        }
        memcpy(out, dom, dlen + 1);
        return 0;
    }

    if (hlen > DNS_FQDN_LIMIT) {
        return ENAMETOOLONG;
    }

    char hostbuf[DNS_FQDN_LIMIT + 1];

    memcpy(hostbuf, host, hlen);
    hostbuf[hlen] = '\0';
    if (!valid_name_chars(hostbuf)) {
        return EINVAL;
    }

    bool already_qualified =
        (hlen == dlen && strncasecmp(hostbuf, dom, dlen) == 0) ||
        (hlen > dlen && hostbuf[hlen - dlen - 1] == '.' &&
         strncasecmp(hostbuf + hlen - dlen, dom, dlen) == 0);

    size_t total = already_qualified ? hlen : hlen + 1 + dlen;

    if (total > DNS_FQDN_LIMIT || total + 1 > cap) {
        return ENAMETOOLONG;
    }

    if (already_qualified) {
        memcpy(out, hostbuf, hlen + 1);
    } else {
        snprintf(out, cap, "%s.%s", hostbuf, dom);
    }
    return 0;
}

bool dns_ip_is_parked(const char *ip) {
    struct in_addr addr;

    if (ip == NULL || inet_pton(AF_INET, ip, &addr) != 1) {
        return false;
    }
    return addr.s_addr == 0u || addr.s_addr == htonl(0x7f000001u);
}

int dns_a_record_with(const dns_ops *ops, void *ud, const char *domain,
                      const char *host, char ip[64], bool *parked) {
    if (ops == NULL || ops->list_servers == NULL || ops->query_a == NULL ||
        domain == NULL || host == NULL || ip == NULL || parked == NULL) {
        return EINVAL;
    }

    char fqdn[DNS_MAX_FQDN + 1];
    int rc = dns_build_fqdn(host, domain, fqdn, sizeof fqdn);

    if (rc != 0) {
        return rc;
    }

    char servers[DNS_MAX_NS][DNS_MAX_SERVER];
    size_t count = 0;

    rc = ops->list_servers(ud, domain, servers, DNS_MAX_NS, &count);
    if (rc != 0) {
        return rc;
    }
    if (count == 0) {
        return ENOENT;
    }
    if (count > DNS_MAX_NS) {
        count = DNS_MAX_NS;
    }

    int last_error = 0;

    for (size_t i = 0; i < count; i++) {
        char answer[64] = "";
        bool found = false;

        rc = ops->query_a(ud, servers[i], fqdn, answer, &found);
        if (rc != 0) {
            last_error = rc;
            continue;
        }
        if (found) {
            /* A success with no answer is malformed, not an empty record. */
            if (answer[0] == '\0') {
                last_error = EIO;
                continue;
            }
            snprintf(ip, 64, "%s", answer);
            *parked = dns_ip_is_parked(ip);
            return 0;
        }
    }

    ip[0] = '\0';
    *parked = false;
    return last_error != 0 ? last_error : ENOENT;
}

int dns_record_exists_with(const dns_ops *ops, void *ud, const char *domain,
                           const char *host, bool *exists) {
    if (ops == NULL || exists == NULL) {
        return EINVAL;
    }
    *exists = false;

    char ip[64];
    bool parked = false;
    int rc = dns_a_record_with(ops, ud, domain, host, ip, &parked);

    if (rc == 0) {
        *exists = true;
        return 0;
    }
    if (rc == ENOENT) {
        return 0;
    }
    return rc;
}

int dns_a_record(const char *domain, const char *host, char ip[64],
                 bool *parked) {
    return dns_a_record_with(dns_cares_ops(), NULL, domain, host, ip, parked);
}

int dns_record_exists(const char *domain, const char *host, bool *exists) {
    return dns_record_exists_with(dns_cares_ops(), NULL, domain, host, exists);
}
