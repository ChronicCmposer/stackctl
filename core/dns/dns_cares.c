/*
 * dns_cares.c — c-ares implementation of the dns_ops seam (spec §5.7).
 *
 * Resolution is two-stage:
 *   1. discover the domain's NS set through the system resolvers;
 *   2. resolve each NS name to IPv4 with a raw type-A query, then send a raw
 *      type-A query for the record to that authoritative server with
 *      ARES_FLAG_NORECURSE so no recursive cache can mask the stored value.
 *
 * The wire-level work (query construction, reply parsing, NS collection from
 * h_aliases) lives in dns_wire.c so it can be tested with synthetic replies.
 * ares_getaddrinfo is deliberately never used: it would consult the hosts file
 * and apply RFC-6724 sorting instead of asking the authoritative server.
 *
 * Every c-ares call is driven by a small select() loop; no global state of our
 * own is kept (the library's init counter is balanced per call).
 */

#include "dns_internal.h"
#include "dns_wire.h"

#include <ares.h>
#include <ares_nameser.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>

#define DNS_QUERY_TIMEOUT_MS 3000

struct ns_result {
    int status;
    int done;
    char names[DNS_MAX_NS][DNS_NS_NAME_CAP];
    size_t count;
};

struct a_result {
    int status;
    int done;
    bool found;
    char ip[64];
};

static int pump(ares_channel_t *channel, int *done) {
    while (!*done) {
        fd_set read_fds;
        fd_set write_fds;

        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        int nfds = ares_fds(channel, &read_fds, &write_fds);

        if (nfds == 0) {
            break;
        }

        struct timeval timeout;
        struct timeval *timeout_ptr = ares_timeout(channel, NULL, &timeout);
        int selected =
            select(nfds, &read_fds, &write_fds, NULL, timeout_ptr);

        if (selected < 0) {
            if (errno == EINTR) {
                continue;
            }
            return EIO;
        }
        ares_process(channel, &read_fds, &write_fds);
    }
    return *done ? 0 : ETIMEDOUT;
}

static ares_channel_t *make_channel(int flags, const struct in_addr *servers,
                                    int nservers, int *error) {
    struct ares_options options;
    int mask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;

    memset(&options, 0, sizeof options);
    options.timeout = DNS_QUERY_TIMEOUT_MS;
    options.tries = 2;

    if (flags != 0) {
        options.flags = flags;
        mask |= ARES_OPT_FLAGS;
    }
    if (servers != NULL && nservers > 0) {
        options.servers = (struct in_addr *)servers;
        options.nservers = nservers;
        mask |= ARES_OPT_SERVERS;
    }

    ares_channel_t *channel = NULL;
    int status = ares_init_options(&channel, &options, mask);

    if (status != ARES_SUCCESS) {
        *error = dns_wire_ares_status_to_errno(status);
        return NULL;
    }
    return channel;
}

static void ns_callback(void *arg, int status, int timeouts,
                        unsigned char *abuf, int alen) {
    struct ns_result *result = arg;

    (void)timeouts;
    if (status != ARES_SUCCESS) {
        result->status = status;
        result->done = 1;
        return;
    }

    size_t count = 0;
    int rc = dns_wire_parse_ns_reply(abuf, alen, result->names, DNS_MAX_NS,
                                     &count);

    if (rc == 0 && count > 0) {
        result->count = count;
        result->status = ARES_SUCCESS;
    } else {
        result->status = rc == ENOENT ? ARES_ENODATA : ARES_EBADRESP;
    }
    result->done = 1;
}

static void a_callback(void *arg, int status, int timeouts,
                       unsigned char *abuf, int alen) {
    struct a_result *wait = arg;

    (void)timeouts;
    wait->status = status;
    if (status == ARES_SUCCESS) {
        char ip[64] = "";
        bool found = false;
        int rc = dns_wire_parse_a_reply(abuf, alen, ip, &found);

        if (rc == 0 && found) {
            snprintf(wait->ip, sizeof wait->ip, "%s", ip);
            wait->found = true;
        } else {
            /* A valid reply with no A answer is "no data", not an error. */
            wait->status = rc == 0 ? ARES_ENODATA : ARES_EBADRESP;
        }
    }
    wait->done = 1;
}

static int run_a_query(ares_channel_t *channel, const char *name, char ip[64],
                       bool *found) {
    struct a_result wait;

    ip[0] = '\0';
    memset(&wait, 0, sizeof wait);
    wait.status = ARES_ENOTFOUND;

    ares_query(channel, name, ns_c_in, ns_t_a, a_callback, &wait);

    int rc = pump(channel, &wait.done);

    if (rc != 0) {
        return rc;
    }
    rc = dns_wire_ares_status_to_errno(wait.status);
    if (rc == ENOENT) {
        *found = false;
        return 0;
    }
    if (rc != 0) {
        return rc;
    }
    if (!wait.found) {
        *found = false;
        return 0;
    }
    snprintf(ip, 64, "%s", wait.ip);
    *found = true;
    return 0;
}

static int cares_list_servers(void *ud, const char *domain,
                              char (*servers)[DNS_MAX_SERVER], size_t max,
                              size_t *count) {
    (void)ud;
    if (domain == NULL || servers == NULL || count == NULL) {
        return EINVAL;
    }
    *count = 0;

    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return EIO;
    }

    int rc = 0;
    ares_channel_t *channel = make_channel(0, NULL, 0, &rc);

    if (channel == NULL) {
        ares_library_cleanup();
        return rc;
    }

    struct ns_result ns;

    memset(&ns, 0, sizeof ns);
    ns.status = ARES_ENOTFOUND;
    ares_query(channel, domain, ns_c_in, ns_t_ns, ns_callback, &ns);

    rc = pump(channel, &ns.done);
    if (rc == 0) {
        rc = dns_wire_ares_status_to_errno(ns.status);
    }

    for (size_t i = 0; rc == 0 && i < ns.count && *count < max; i++) {
        char ip[64];
        bool found = false;

        if (run_a_query(channel, ns.names[i], ip, &found) != 0 || !found) {
            continue;
        }

        bool duplicate = false;
        for (size_t j = 0; j < *count; j++) {
            if (strcmp(servers[j], ip) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            snprintf(servers[*count], DNS_MAX_SERVER, "%s", ip);
            (*count)++;
        }
    }

    ares_destroy(channel);
    ares_library_cleanup();

    if (rc != 0) {
        return rc;
    }
    return *count > 0 ? 0 : ENOENT;
}

static int cares_query_a(void *ud, const char *server_ip, const char *fqdn,
                         char ip[64], bool *found) {
    (void)ud;
    if (server_ip == NULL || fqdn == NULL || ip == NULL || found == NULL) {
        return EINVAL;
    }
    *found = false;

    struct in_addr server;

    if (inet_pton(AF_INET, server_ip, &server) != 1) {
        return EINVAL;
    }

    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return EIO;
    }

    int rc = 0;
    ares_channel_t *channel =
        make_channel(ARES_FLAG_NORECURSE, &server, 1, &rc);

    if (channel == NULL) {
        ares_library_cleanup();
        return rc;
    }

    bool present = false;
    rc = run_a_query(channel, fqdn, ip, &present);

    ares_destroy(channel);
    ares_library_cleanup();

    if (rc != 0) {
        return rc;
    }
    *found = present;
    return 0;
}

const dns_ops *dns_cares_ops(void) {
    static const dns_ops ops = {
        .list_servers = cares_list_servers,
        .query_a = cares_query_a,
    };
    return &ops;
}
