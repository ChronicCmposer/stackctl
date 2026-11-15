/*
 * ddns.c — Namecheap dynamic-DNS client (spec §5.7).
 *
 * The transport lives behind the injectable ddns_http_ops seam (ddns_curl.c
 * in production); this file builds the update request, parses the XML
 * response, redacts credentials from diagnostics, and parses IP-echo bodies.
 */

#include "ddns.h"
#include "ddns_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define DDNS_BODY_CAP 8192

static bool ipv4_valid(const char *ip) {
    struct in_addr addr;

    return ip != NULL && inet_pton(AF_INET, ip, &addr) == 1;
}

static int append_raw(const char *text, char *out, size_t cap, size_t *pos) {
    size_t len = strlen(text);

    if (*pos + len + 1 > cap) {
        return ENAMETOOLONG;
    }
    memcpy(out + *pos, text, len);
    *pos += len;
    out[*pos] = '\0';
    return 0;
}

static int append_encoded(const char *text, char *out, size_t cap,
                          size_t *pos) {
    static const char hex[] = "0123456789ABCDEF";

    for (const unsigned char *p = (const unsigned char *)text; *p != '\0';
         p++) {
        if (isalnum(*p) || *p == '-' || *p == '.' || *p == '_' || *p == '~') {
            if (*pos + 2 > cap) {
                return ENAMETOOLONG;
            }
            out[(*pos)++] = (char)*p;
        } else {
            if (*pos + 4 > cap) {
                return ENAMETOOLONG;
            }
            out[(*pos)++] = '%';
            out[(*pos)++] = hex[*p >> 4];
            out[(*pos)++] = hex[*p & 0x0f];
        }
        out[*pos] = '\0';
    }
    return 0;
}

int ddns_build_update_url(const char *host, const char *domain,
                          const char *password, const char *ip, char *out,
                          size_t cap) {
    if (host == NULL || domain == NULL || password == NULL || ip == NULL ||
        out == NULL || cap == 0) {
        return EINVAL;
    }
    if (host[0] == '\0' || domain[0] == '\0' || password[0] == '\0') {
        return EINVAL;
    }
    if (!ipv4_valid(ip)) {
        return EINVAL;
    }

    size_t pos = 0;
    int rc;

    out[0] = '\0';
    rc = append_raw(DDNS_UPDATE_BASE "?host=", out, cap, &pos);
    if (rc == 0) {
        rc = append_encoded(host, out, cap, &pos);
    }
    if (rc == 0) {
        rc = append_raw("&domain=", out, cap, &pos);
    }
    if (rc == 0) {
        rc = append_encoded(domain, out, cap, &pos);
    }
    if (rc == 0) {
        rc = append_raw("&password=", out, cap, &pos);
    }
    if (rc == 0) {
        rc = append_encoded(password, out, cap, &pos);
    }
    if (rc == 0) {
        rc = append_raw("&ip=", out, cap, &pos);
    }
    if (rc == 0) {
        rc = append_encoded(ip, out, cap, &pos);
    }
    return rc;
}

int ddns_redact_url(const char *url, char *out, size_t cap) {
    static const char marker[] = "password=";

    if (url == NULL || out == NULL || cap == 0) {
        return EINVAL;
    }

    const char *found = strstr(url, marker);
    if (found == NULL) {
        if (strlen(url) + 1 > cap) {
            return ENAMETOOLONG;
        }
        memcpy(out, url, strlen(url) + 1);
        return 0;
    }

    size_t prefix = (size_t)(found - url) + strlen(marker);
    const char *value_end = strchr(found + strlen(marker), '&');
    const char *tail = value_end != NULL ? value_end : url + strlen(url);
    size_t needed = prefix + strlen("REDACTED") + strlen(tail) + 1;

    if (needed > cap) {
        return ENAMETOOLONG;
    }
    memcpy(out, url, prefix);
    memcpy(out + prefix, "REDACTED", strlen("REDACTED"));
    memcpy(out + prefix + strlen("REDACTED"), tail, strlen(tail) + 1);
    return 0;
}

static const char *find_tag(const char *body, const char *tag) {
    return strstr(body, tag);
}

int ddns_parse_response(const char *body, bool *updated, char *error_text,
                        size_t error_cap) {
    if (body == NULL || updated == NULL) {
        return EINVAL;
    }
    if (error_text != NULL && error_cap > 0) {
        error_text[0] = '\0';
    }

    const char *open = find_tag(body, "<ErrCount>");
    if (open == NULL) {
        return EINVAL;
    }
    const char *cursor = open + strlen("<ErrCount>");

    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
           *cursor == '\n') {
        cursor++;
    }
    if (!isdigit((unsigned char)*cursor)) {
        return EINVAL;
    }

    long err_count = 0;

    while (isdigit((unsigned char)*cursor)) {
        if (err_count > 1000000L) {
            return EINVAL;
        }
        err_count = err_count * 10 + (*cursor - '0');
        cursor++;
    }
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
           *cursor == '\n') {
        cursor++;
    }
    if (strncmp(cursor, "</ErrCount>", strlen("</ErrCount>")) != 0) {
        return EINVAL;
    }

    if (err_count == 0) {
        *updated = true;
        return 0;
    }

    *updated = false;
    if (error_text == NULL || error_cap == 0) {
        return 0;
    }

    for (int index = 1; index <= 20; index++) {
        char open_tag[16];
        char close_tag[16];

        snprintf(open_tag, sizeof open_tag, "<Err%d>", index);
        snprintf(close_tag, sizeof close_tag, "</Err%d>", index);

        const char *first = find_tag(body, open_tag);
        if (first == NULL) {
            continue;
        }
        const char *text = first + strlen(open_tag);
        const char *last = find_tag(text, close_tag);

        if (last == NULL || last == text) {
            continue;
        }
        size_t length = (size_t)(last - text);

        if (length >= error_cap) {
            length = error_cap - 1;
        }
        memcpy(error_text, text, length);
        error_text[length] = '\0';
        return 0;
    }

    snprintf(error_text, error_cap, "Namecheap reported an error");
    return 0;
}

static int strip_nuls(const char *source, size_t length, char *out,
                      size_t cap) {
    size_t out_len = 0;

    for (size_t i = 0; i < length; i++) {
        if (source[i] == '\0') {
            continue;
        }
        if (out_len + 1 >= cap) {
            return EOVERFLOW;
        }
        out[out_len++] = source[i];
    }
    out[out_len] = '\0';
    return 0;
}

int ddns_parse_echo_ip(const char *body, char ip[64]) {
    if (body == NULL || ip == NULL) {
        return EINVAL;
    }

    char clean[256];

    int rc = strip_nuls(body, strlen(body), clean, sizeof clean);

    if (rc != 0) {
        return rc;
    }

    char *start = clean;
    while (*start == ' ' || *start == '\t' || *start == '\r' ||
           *start == '\n') {
        start++;
    }
    /* An echo body is a single token; ignore any trailing noise (or a NUL
     * run collapsed by strip_nuls) after the first whitespace. */
    char *end = start;
    while (*end != '\0' && !isspace((unsigned char)*end)) {
        end++;
    }
    *end = '\0';

    struct in_addr addr;

    if (*start == '\0' || inet_pton(AF_INET, start, &addr) != 1) {
        return EINVAL;
    }
    snprintf(ip, 64, "%s", start);
    return 0;
}

int ddns_update_with(const ddns_http_ops *ops, void *ud, const char *host,
                     const char *domain, const char *password, const char *ip,
                     bool *updated) {
    if (ops == NULL || ops->get == NULL || host == NULL || domain == NULL ||
        password == NULL || ip == NULL || updated == NULL) {
        return EINVAL;
    }
    *updated = false;
    if (!ipv4_valid(ip)) {
        return EINVAL;
    }

    char url[1024];
    int rc = ddns_build_update_url(host, domain, password, ip, url,
                                   sizeof url);

    if (rc != 0) {
        return rc;
    }

    char body[DDNS_BODY_CAP];
    size_t length = 0;
    long status = 0;

    rc = ops->get(ud, url, body, sizeof body, &length, &status);
    if (rc != 0) {
        return rc;
    }
    if (length >= sizeof body) {
        return EOVERFLOW;
    }

    char clean[DDNS_BODY_CAP];

    rc = strip_nuls(body, length, clean, sizeof clean);
    if (rc != 0) {
        return rc;
    }

    char error_text[256];
    bool success = false;

    rc = ddns_parse_response(clean, &success, error_text, sizeof error_text);
    if (rc != 0) {
        return rc;
    }
    if (!success) {
        fprintf(stderr, "ddns: Namecheap update failed: %s\n", error_text);
        return EPROTO;
    }

    *updated = true;
    return 0;
}

int ddns_ip_echo_with(const ddns_http_ops *ops, void *ud, const char *url,
                      char ip[64]) {
    if (ops == NULL || ops->get == NULL || url == NULL || ip == NULL) {
        return EINVAL;
    }
    if (strncmp(url, "https://", strlen("https://")) != 0 &&
        strncmp(url, "http://", strlen("http://")) != 0) {
        return EINVAL;
    }

    char body[DDNS_BODY_CAP];
    size_t length = 0;
    long status = 0;
    int rc = ops->get(ud, url, body, sizeof body, &length, &status);

    if (rc != 0) {
        return rc;
    }
    if (status < 200 || status >= 300) {
        return EPROTO;
    }
    if (length >= sizeof body) {
        return EOVERFLOW;
    }

    char clean[DDNS_BODY_CAP];

    rc = strip_nuls(body, length, clean, sizeof clean);
    if (rc != 0) {
        return rc;
    }
    return ddns_parse_echo_ip(clean, ip);
}

int ddns_update(const char *host, const char *domain, const char *password,
                const char *ip, bool *updated) {
    return ddns_update_with(ddns_curl_ops(), NULL, host, domain, password, ip,
                            updated);
}

int ddns_ip_echo(const char *url, char ip[64]) {
    return ddns_ip_echo_with(ddns_curl_ops(), NULL, url, ip);
}
