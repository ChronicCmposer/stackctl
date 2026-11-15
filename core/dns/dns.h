/*
 * dns.h — authoritative A-record reads for stackctl DDNS (spec §5.7).
 *
 * The Namecheap DDNS endpoint is write-only, so every read goes to the
 * domain's authoritative nameservers: this module discovers the NS set with
 * c-ares and queries the authoritative servers directly with recursion
 * disabled, so no recursive cache can mask the stored value.
 *
 * Error model (CONTRACT.md): 0 on success, non-zero errno-style code otherwise.
 * "No A record" is reported as ENOENT by dns_a_record().
 */

#ifndef STACKCTL_DNS_H
#define STACKCTL_DNS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resolve the A record for `host` in `domain` via the domain's authoritative
 * nameservers. `host` may be a label ("box"), "@" or "" for the apex, or a
 * fully-qualified name that already ends in `domain`.
 *
 * On success `ip` receives the dotted-quad address (at least 64 bytes of
 * storage required) and `*parked` reports whether it is a Namecheap
 * placeholder (0.0.0.0 or 127.0.0.1). Returns 0, ENOENT when no A record
 * exists, or another errno-style code on resolution failure.
 */
int dns_a_record(const char *domain, const char *host, char ip[64],
                 bool *parked);

/*
 * Report whether an A record currently exists for `host` in `domain`.
 * Returns 0 with `*exists` set, or a non-zero errno-style code.
 */
int dns_record_exists(const char *domain, const char *host, bool *exists);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_DNS_H */
