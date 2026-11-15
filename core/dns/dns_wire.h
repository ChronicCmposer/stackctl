/*
 * dns_wire.h — raw DNS query/reply helpers for core/dns (spec §5.7).
 *
 * The production resolver is c-ares (dns_cares.c), but the parts that decide
 * *what* is asked and *how* a reply is interpreted are pure functions over the
 * wire format. Keeping them here lets the tests feed synthetic replies and pin
 * authoritative behaviour (raw type-A queries, NS names from h_aliases only)
 * without opening a socket (CONTRACT Amendment 4).
 *
 * These helpers deliberately avoid ares_getaddrinfo: the resolver must never
 * consult the hosts file or apply RFC-6724 sorting.
 */

#ifndef STACKCTL_DNS_WIRE_H
#define STACKCTL_DNS_WIRE_H

#include <stdbool.h>
#include <stddef.h>

#include "dns_internal.h"

#define DNS_NS_NAME_CAP 256

/*
 * Build a class-IN, type-A query for `fqdn` (forced recursion-desired bit set
 * on the wire; the authoritative-only guarantee comes from the channel's
 * ARES_FLAG_NORECURSE + ARES_OPT_SERVERS options). Returns 0 with *len set,
 * EINVAL on bad input, ENAMETOOLONG when `cap` is too small, or another
 * errno-style code on c-ares failure.
 */
int dns_wire_build_a_query(const char *fqdn, unsigned char *buf, int cap,
                           int *len);

/*
 * Parse a raw reply to an A query. Returns 0 with *found reporting whether an
 * IPv4 answer was present (and `ip` filled with its dotted quad); an answer
 * section with no usable A record is a valid success with *found == false.
 * Non-zero errno-style codes report a malformed reply.
 */
int dns_wire_parse_a_reply(const unsigned char *abuf, int alen, char ip[64],
                           bool *found);

/*
 * Parse a raw reply to an NS query. Only answer-section NS targets are
 * collected — `h_aliases` from ares_parse_ns_reply, never `h_name` (which is
 * the queried domain, not a nameserver). Returns 0 with *count > 0, ENOENT
 * when the reply carries no NS records, or another errno-style code.
 */
int dns_wire_parse_ns_reply(const unsigned char *abuf, int alen,
                            char (*names)[DNS_NS_NAME_CAP], size_t max,
                            size_t *count);

/* Map a c-ares status code to this module's errno-style error model. */
int dns_wire_ares_status_to_errno(int status);

#endif /* STACKCTL_DNS_WIRE_H */
