/*
 * ddns.h — Namecheap dynamic-DNS client (spec §5.7).
 *
 * The Namecheap /update endpoint authenticates with only host + domain + the
 * domain's DDNS password. It is update-only: it cannot create, delete, or
 * read records. Success is parsed from the XML response body
 * (<ErrCount>0</ErrCount>), never from the HTTP status alone. The password is
 * supplied by the caller (from SSM / a file), never from argv, and is never
 * logged.
 *
 * Error model (CONTRACT.md): 0 on success, non-zero errno-style code otherwise.
 */

#ifndef STACKCTL_DDNS_H
#define STACKCTL_DDNS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Update the pre-existing A record for `host` in `domain` to `ip`.
 *
 * `host` and `domain` are case-sensitive (as the endpoint is); `password` is
 * the per-domain DDNS password. On a successful Namecheap response `*updated`
 * is true. On an endpoint-reported failure `*updated` is false, the error text
 * is written to stderr (credential-free), and a non-zero code is returned.
 */
int ddns_update(const char *host, const char *domain, const char *password,
                const char *ip, bool *updated);

/*
 * Fetch a public-IP echo URL over HTTPS and parse the returned IPv4 address
 * into `ip` (at least 64 bytes of storage). Used by `status`. Returns 0,
 * EINVAL/EPROTO for bad input or an unparseable body, or another errno-style
 * code on transport failure.
 */
int ddns_ip_echo(const char *url, char ip[64]);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_DDNS_H */
