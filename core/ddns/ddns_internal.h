/*
 * ddns_internal.h — injectable HTTP seam and pure helpers for core/ddns.
 *
 * Tests substitute a ddns_http_ops implementation so request construction,
 * XML parsing, credential redaction, and IP-echo parsing are exercised with
 * fixed vectors and no network access (CONTRACT Amendment 4).
 */

#ifndef STACKCTL_DDNS_INTERNAL_H
#define STACKCTL_DDNS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

/* Base URL frozen by spec §5.7; the endpoint is update-only. */
#define DDNS_UPDATE_BASE "https://dynamicdns.park-your-domain.com/update"

typedef struct ddns_http_ops {
    /*
     * Perform a GET of `url`. The response body is written NUL-terminated to
     * `body` (capacity `cap`, at most cap-1 bytes) and its length reported in
     * `len`; `status` receives the HTTP status code (0 if unavailable).
     * Returns 0 on transport success, else a non-zero errno-style code.
     */
    int (*get)(void *ud, const char *url, char *body, size_t cap, size_t *len,
               long *status);
} ddns_http_ops;

int ddns_update_with(const ddns_http_ops *ops, void *ud, const char *host,
                     const char *domain, const char *password, const char *ip,
                     bool *updated);
int ddns_ip_echo_with(const ddns_http_ops *ops, void *ud, const char *url,
                      char ip[64]);

/*
 * Build the signed update URL. Parameters appear in the fixed order
 * host, domain, password, ip; values are RFC 3986 percent-encoded. Returns 0,
 * EINVAL on bad input, ENAMETOOLONG when `cap` is too small.
 */
int ddns_build_update_url(const char *host, const char *domain,
                          const char *password, const char *ip, char *out,
                          size_t cap);

/*
 * Parse a Namecheap XML body. Embedded NUL bytes are stripped first. Returns 0
 * when <ErrCount> is present (with `*updated` set and, on failure, the first
 * <ErrN> text copied into `error_text`), EINVAL when the body is not a
 * recognisable Namecheap response.
 */
int ddns_parse_response(const char *body, bool *updated, char *error_text,
                        size_t error_cap);

/*
 * Replace the value of the password query parameter with "REDACTED" so a URL
 * can be shown in diagnostics without leaking the credential. Returns 0,
 * EINVAL on bad input, ENAMETOOLONG when `cap` is too small.
 */
int ddns_redact_url(const char *url, char *out, size_t cap);

/*
 * Parse an IP-echo response body: strip NULs and surrounding whitespace, then
 * require a dotted-quad IPv4. Returns 0, EINVAL/EPROTO otherwise.
 */
int ddns_parse_echo_ip(const char *body, char ip[64]);

/* libcurl-backed production implementation of ddns_http_ops. */
const ddns_http_ops *ddns_curl_ops(void);

#endif /* STACKCTL_DDNS_INTERNAL_H */
