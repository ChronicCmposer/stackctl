/*
 * dns_internal.h — injectable resolver seam and pure helpers for core/dns.
 *
 * The public surface (dns.h) talks to c-ares; tests substitute a dns_ops
 * implementation so the authoritative-NS iteration, parked detection, and
 * error semantics can be exercised without any network access (CONTRACT
 * Amendment 4).
 */

#ifndef STACKCTL_DNS_INTERNAL_H
#define STACKCTL_DNS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#define DNS_MAX_NS 16
#define DNS_MAX_SERVER 64
#define DNS_MAX_FQDN 254

typedef struct dns_ops {
    /*
     * Discover the authoritative nameservers for `domain`, writing up to
     * `max` IPv4 server addresses into `servers` (each a NUL-terminated
     * dotted quad, DNS_MAX_SERVER bytes). Returns 0 and sets *count.
     */
    int (*list_servers)(void *ud, const char *domain,
                        char (*servers)[DNS_MAX_SERVER], size_t max,
                        size_t *count);

    /*
     * Query the A record for `fqdn` at a single authoritative `server_ip`
     * with recursion disabled. Returns 0 on success (with *found reporting
     * presence), or a non-zero errno-style code.
     */
    int (*query_a)(void *ud, const char *server_ip, const char *fqdn,
                   char ip[64], bool *found);
} dns_ops;

/* Seam-injected entry points used by dns_a_record()/dns_record_exists(). */
int dns_a_record_with(const dns_ops *ops, void *ud, const char *domain,
                      const char *host, char ip[64], bool *parked);
int dns_record_exists_with(const dns_ops *ops, void *ud, const char *domain,
                           const char *host, bool *exists);

/*
 * Build the query name for host+domain. Accepts a bare label, "@"/"" for the
 * apex, and an already-qualified host that ends in `domain` (case-insensitive,
 * trailing dots tolerated). Returns 0, EINVAL on bad input, ENAMETOOLONG when
 * the result cannot fit `cap` or exceeds 253 characters.
 */
int dns_build_fqdn(const char *host, const char *domain, char *out, size_t cap);

/* True only for the exact Namecheap placeholders 0.0.0.0 and 127.0.0.1. */
bool dns_ip_is_parked(const char *ip);

/* c-ares-backed production implementation of dns_ops. */
const dns_ops *dns_cares_ops(void);

#endif /* STACKCTL_DNS_INTERNAL_H */
