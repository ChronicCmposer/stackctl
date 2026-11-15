/*
 * dns_wire.c — raw DNS query/reply helpers for core/dns (spec §5.7).
 *
 * Pure(ish) functions over c-ares wire buffers: build a type-A query, parse an
 * A reply, and parse an NS reply. They never resolve names (no hosts file, no
 * RFC-6724 sorting) and never touch a socket, so the tests can drive them with
 * synthetic replies (CONTRACT Amendment 4).
 */

#include "dns_wire.h"

#include <ares.h>
#include <ares_nameser.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#define DNS_WIRE_MAX_A 8

int dns_wire_ares_status_to_errno(int status) {
    switch (status) {
    case ARES_SUCCESS:
        return 0;
    case ARES_ENOTFOUND:
    case ARES_ENODATA:
        return ENOENT;
    case ARES_ETIMEOUT:
        return ETIMEDOUT;
    case ARES_ENOMEM:
        return ENOMEM;
    case ARES_ECONNREFUSED:
        return ECONNREFUSED;
    default:
        return EIO;
    }
}

int dns_wire_build_a_query(const char *fqdn, unsigned char *buf, int cap,
                           int *len) {
    if (fqdn == NULL || buf == NULL || len == NULL || cap <= 0) {
        return EINVAL;
    }
    *len = 0;

    unsigned char *query = NULL;
    int query_len = 0;
    /* rd=1 only sets the wire bit; the authoritative guarantee is the
     * channel's ARES_FLAG_NORECURSE + ARES_OPT_SERVERS configuration. */
    int status = ares_create_query(fqdn, ns_c_in, ns_t_a, 0, 1, &query,
                                   &query_len, 0);

    if (status != ARES_SUCCESS) {
        return dns_wire_ares_status_to_errno(status);
    }
    if (query_len <= 0) {
        ares_free_string(query);
        return EIO;
    }
    if (query_len > cap) {
        ares_free_string(query);
        return ENAMETOOLONG;
    }

    memcpy(buf, query, (size_t)query_len);
    ares_free_string(query);
    *len = query_len;
    return 0;
}

int dns_wire_parse_a_reply(const unsigned char *abuf, int alen, char ip[64],
                           bool *found) {
    if (abuf == NULL || alen <= 0 || ip == NULL || found == NULL) {
        return EINVAL;
    }
    *found = false;
    ip[0] = '\0';

    struct ares_addrttl answers[DNS_WIRE_MAX_A];
    int count = (int)(sizeof answers / sizeof answers[0]);
    int status = ares_parse_a_reply(abuf, alen, NULL, answers, &count);

    if (status == ARES_ENODATA) {
        return 0;
    }
    if (status != ARES_SUCCESS) {
        return dns_wire_ares_status_to_errno(status);
    }
    if (count <= 0) {
        return 0;
    }
    if (inet_ntop(AF_INET, &answers[0].ipaddr, ip, 64) == NULL) {
        return EIO;
    }
    *found = true;
    return 0;
}

static void add_ns_name(char (*names)[DNS_NS_NAME_CAP], size_t max,
                        size_t *count, const char *name) {
    if (name == NULL || name[0] == '\0' || *count >= max) {
        return;
    }

    size_t length = strlen(name);

    while (length > 0 && name[length - 1] == '.') {
        length--;
    }
    if (length == 0 || length >= DNS_NS_NAME_CAP) {
        return;
    }

    for (size_t i = 0; i < *count; i++) {
        if (strncmp(names[i], name, length) == 0 && names[i][length] == '\0') {
            return;
        }
    }

    memcpy(names[*count], name, length);
    names[*count][length] = '\0';
    (*count)++;
}

int dns_wire_parse_ns_reply(const unsigned char *abuf, int alen,
                            char (*names)[DNS_NS_NAME_CAP], size_t max,
                            size_t *count) {
    if (abuf == NULL || alen <= 0 || names == NULL || count == NULL ||
        max == 0) {
        return EINVAL;
    }
    *count = 0;

    struct hostent *host = NULL;
    int status = ares_parse_ns_reply(abuf, alen, &host);

    if (status != ARES_SUCCESS || host == NULL) {
        if (host != NULL) {
            ares_free_hostent(host);
        }
        return status == ARES_SUCCESS ? ENOENT
                                      : dns_wire_ares_status_to_errno(status);
    }

    /*
     * ares_parse_ns_reply sets h_name to the *queried* name and puts the
     * answer-section NS targets in h_aliases. Only the aliases are real
     * authoritative servers; injecting h_name would send the first NORECURSE
     * A query back to the domain's own A-record host.
     */
    for (char **alias = host->h_aliases; alias != NULL && *alias != NULL;
         alias++) {
        add_ns_name(names, max, count, *alias);
    }

    ares_free_hostent(host);
    return *count > 0 ? 0 : ENOENT;
}
