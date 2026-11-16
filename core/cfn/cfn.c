/*
 * cfn.c — CloudFormation Query-protocol request builders, XML response
 * parsers, status mapping, error translation and bounded waiters.
 *
 * Requests are form-encoded (`Action=...&Version=2010-05-15&...`) POSTed to
 * `/` with `application/x-www-form-urlencoded; charset=utf-8` through the
 * injected aws transport seam. Responses are AWS Query XML, parsed by a small
 * internal DOM (elements, text, entities) instead of a general XML dependency.
 */

#include "cfn_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFN_API_VERSION "2010-05-15"
#define CFN_CONTENT_TYPE "application/x-www-form-urlencoded; charset=utf-8"
#define CFN_MAX_PAGES 1000

struct cfn_client {
    aws_ctx *aws;
    cfn_transport_fn send;
    void *ud;
};

/* ------------------------------------------------------------ string buffer */

typedef struct sbuf {
    char *data;
    size_t len;
    size_t cap;
} sbuf;

static void sb_free(sbuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static int sb_reserve(sbuf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) {
        return 0;
    }
    size_t cap = b->cap == 0 ? 128 : b->cap;
    while (cap < b->len + extra + 1) {
        if (cap > SIZE_MAX / 2) {
            return ENOMEM;
        }
        cap *= 2;
    }
    char *grown = realloc(b->data, cap);
    if (grown == NULL) {
        return ENOMEM;
    }
    b->data = grown;
    b->cap = cap;
    return 0;
}

static int sb_putn(sbuf *b, const char *s, size_t n)
{
    int rc = sb_reserve(b, n);
    if (rc != 0) {
        return rc;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

static int sb_putc(sbuf *b, char c)
{
    return sb_putn(b, &c, 1);
}

/* --------------------------------------------------------- XML DOM parser */

typedef struct xnode {
    char *name;
    char *text;
    struct xnode **kids;
    size_t kid_count;
    size_t kid_cap;
} xnode;

typedef struct xparser {
    const char *p;
} xparser;

static int ascii_ieq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int ascii_icontains(const char *haystack, const char *needle)
{
    if (needle[0] == '\0') {
        return 1;
    }
    for (const char *p = haystack; *p != '\0'; p++) {
        if (ascii_ieq(p, needle)) {
            return 1;
        }
        size_t i = 0;
        while (needle[i] != '\0' && p[i] != '\0' &&
               tolower((unsigned char)p[i]) ==
                   tolower((unsigned char)needle[i])) {
            i++;
        }
        if (needle[i] == '\0') {
            return 1;
        }
    }
    return 0;
}

static const char *skip_space(const char *p)
{
    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static int starts_with(const char *p, const char *literal)
{
    return strncmp(p, literal, strlen(literal)) == 0;
}

static int append_entity(sbuf *out, const char *entity, size_t len)
{
    if (len == 3 && strncmp(entity, "amp", 3) == 0) {
        return sb_putc(out, '&');
    }
    if (len == 2 && strncmp(entity, "lt", 2) == 0) {
        return sb_putc(out, '<');
    }
    if (len == 2 && strncmp(entity, "gt", 2) == 0) {
        return sb_putc(out, '>');
    }
    if (len == 4 && strncmp(entity, "quot", 4) == 0) {
        return sb_putc(out, '"');
    }
    if (len == 4 && strncmp(entity, "apos", 4) == 0) {
        return sb_putc(out, '\'');
    }
    if (len >= 2 && entity[0] == '#') {
        unsigned long value = 0;
        size_t i = 1;
        int base = 10;
        if (entity[i] == 'x' || entity[i] == 'X') {
            base = 16;
            i++;
        }
        if (i >= len) {
            return EPROTO;
        }
        for (; i < len; i++) {
            int digit;
            char c = entity[i];
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (base == 16 && c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else if (base == 16 && c >= 'A' && c <= 'F') {
                digit = c - 'A' + 10;
            } else {
                return EPROTO;
            }
            value = value * (unsigned long)base + (unsigned long)digit;
        }
        if (value == 0 || value > 0x7f) {
            return sb_putc(out, '?');
        }
        return sb_putc(out, (char)value);
    }
    /* Unknown entity: keep it verbatim so data is never silently lost. */
    if (sb_putc(out, '&') != 0 || sb_putn(out, entity, len) != 0) {
        return ENOMEM;
    }
    return 0;
}

static int append_decoded(sbuf *out, const char *s, size_t len)
{
    size_t i = 0;
    while (i < len) {
        if (s[i] != '&') {
            if (sb_putc(out, s[i]) != 0) {
                return ENOMEM;
            }
            i++;
            continue;
        }
        size_t end = i + 1;
        while (end < len && s[end] != ';') {
            end++;
        }
        if (end >= len) {
            if (sb_putc(out, '&') != 0) {
                return ENOMEM;
            }
            i++;
            continue;
        }
        int rc = append_entity(out, s + i + 1, end - i - 1);
        if (rc != 0) {
            return rc;
        }
        i = end + 1;
    }
    return 0;
}

static void xnode_free(xnode *node)
{
    if (node == NULL) {
        return;
    }
    free(node->name);
    free(node->text);
    for (size_t i = 0; i < node->kid_count; i++) {
        xnode_free(node->kids[i]);
    }
    free(node->kids);
    free(node);
}

static int xnode_add(xnode *parent, xnode *child)
{
    if (parent->kid_count == parent->kid_cap) {
        size_t cap = parent->kid_cap == 0 ? 4 : parent->kid_cap * 2;
        xnode **grown = realloc(parent->kids, cap * sizeof(*grown));
        if (grown == NULL) {
            return ENOMEM;
        }
        parent->kids = grown;
        parent->kid_cap = cap;
    }
    parent->kids[parent->kid_count++] = child;
    return 0;
}

/* Read an element name at *pp (just after '<'), stripping any namespace
 * prefix. Returns a heap string and advances *pp past the name. */
static int read_name(const char **pp, char **out)
{
    const char *p = *pp;
    const char *start = p;
    while (*p != '\0' && *p != '>' && *p != '/' && !isspace((unsigned char)*p)) {
        p++;
    }
    if (p == start) {
        return EPROTO;
    }
    const char *local = start;
    for (const char *q = start; q < p; q++) {
        if (*q == ':') {
            local = q + 1;
        }
    }
    size_t len = (size_t)(p - local);
    char *name = malloc(len + 1);
    if (name == NULL) {
        return ENOMEM;
    }
    memcpy(name, local, len);
    name[len] = '\0';
    *pp = p;
    *out = name;
    return 0;
}

static const char *skip_attributes(const char *p)
{
    char quote = 0;
    while (*p != '\0') {
        if (quote != 0) {
            if (*p == quote) {
                quote = 0;
            }
        } else if (*p == '"' || *p == '\'') {
            quote = *p;
        } else if (*p == '>') {
            return p;
        }
        p++;
    }
    return p;
}

static int skip_until(const char **pp, const char *terminator)
{
    const char *found = strstr(*pp, terminator);
    if (found == NULL) {
        return EPROTO;
    }
    *pp = found + strlen(terminator);
    return 0;
}

static int parse_element(xparser *ps, xnode **out)
{
    const char *p = skip_space(ps->p);
    if (*p != '<' || p[1] == '/' || p[1] == '!' || p[1] == '?') {
        return EPROTO;
    }
    p++;
    xnode *node = calloc(1, sizeof(*node));
    if (node == NULL) {
        return ENOMEM;
    }
    int rc = read_name(&p, &node->name);
    if (rc != 0) {
        xnode_free(node);
        return rc;
    }
    p = skip_space(p);
    if (p[0] == '/' && p[1] == '>') {
        node->text = strdup("");
        if (node->text == NULL) {
            xnode_free(node);
            return ENOMEM;
        }
        ps->p = p + 2;
        *out = node;
        return 0;
    }
    if (*p != '>') {
        p = skip_attributes(p);
    }
    if (*p != '>') {
        xnode_free(node);
        return EPROTO;
    }
    p++;

    sbuf text = {0};
    for (;;) {
        if (*p == '\0') {
            sb_free(&text);
            xnode_free(node);
            return EPROTO;
        }
        if (starts_with(p, "</")) {
            p += 2;
            char *close_name = NULL;
            rc = read_name(&p, &close_name);
            if (rc != 0) {
                sb_free(&text);
                xnode_free(node);
                return rc;
            }
            int matches = strcmp(close_name, node->name) == 0;
            free(close_name);
            p = skip_space(p);
            if (!matches || *p != '>') {
                sb_free(&text);
                xnode_free(node);
                return EPROTO;
            }
            p++;
            break;
        }
        if (starts_with(p, "<!--")) {
            p += 4;
            rc = skip_until(&p, "-->");
            if (rc != 0) {
                sb_free(&text);
                xnode_free(node);
                return rc;
            }
            continue;
        }
        if (starts_with(p, "<?")) {
            p += 2;
            rc = skip_until(&p, "?>");
            if (rc != 0) {
                sb_free(&text);
                xnode_free(node);
                return rc;
            }
            continue;
        }
        if (starts_with(p, "<![CDATA[")) {
            p += 9;
            const char *end = strstr(p, "]]>");
            if (end == NULL) {
                sb_free(&text);
                xnode_free(node);
                return EPROTO;
            }
            if (sb_putn(&text, p, (size_t)(end - p)) != 0) {
                sb_free(&text);
                xnode_free(node);
                return ENOMEM;
            }
            p = end + 3;
            continue;
        }
        if (*p == '<') {
            xnode *child = NULL;
            ps->p = p;
            rc = parse_element(ps, &child);
            if (rc != 0) {
                sb_free(&text);
                xnode_free(node);
                return rc;
            }
            rc = xnode_add(node, child);
            if (rc != 0) {
                xnode_free(child);
                sb_free(&text);
                xnode_free(node);
                return rc;
            }
            p = ps->p;
            continue;
        }
        const char *start = p;
        while (*p != '\0' && *p != '<') {
            p++;
        }
        rc = append_decoded(&text, start, (size_t)(p - start));
        if (rc != 0) {
            sb_free(&text);
            xnode_free(node);
            return rc;
        }
    }

    if (text.data == NULL) {
        text.data = strdup("");
        if (text.data == NULL) {
            xnode_free(node);
            return ENOMEM;
        }
    }
    node->text = text.data;
    ps->p = p;
    *out = node;
    return 0;
}

static int parse_document(const char *xml, xnode **out)
{
    if (xml == NULL) {
        return EPROTO;
    }
    xparser ps = {.p = xml};
    const char *p = skip_space(ps.p);
    while (starts_with(p, "<?") || starts_with(p, "<!--") ||
           starts_with(p, "<!")) {
        if (starts_with(p, "<?")) {
            int rc = skip_until(&p, "?>");
            if (rc != 0) {
                return rc;
            }
        } else if (starts_with(p, "<!--")) {
            int rc = skip_until(&p, "-->");
            if (rc != 0) {
                return rc;
            }
        } else {
            int rc = skip_until(&p, ">");
            if (rc != 0) {
                return rc;
            }
        }
        p = skip_space(p);
    }
    ps.p = p;
    int rc = parse_element(&ps, out);
    if (rc != 0) {
        return rc;
    }
    if (*skip_space(ps.p) != '\0') {
        xnode_free(*out);
        *out = NULL;
        return EPROTO;
    }
    return 0;
}

static const xnode *xchild(const xnode *node, const char *name)
{
    if (node == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < node->kid_count; i++) {
        if (strcmp(node->kids[i]->name, name) == 0) {
            return node->kids[i];
        }
    }
    return NULL;
}

/* Copy trimmed element text into a fixed buffer; absent element -> "". */
static int xcopy(const xnode *node, char *dst, size_t cap)
{
    const char *s = node != NULL && node->text != NULL ? node->text : "";
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    const char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    size_t len = (size_t)(end - s);
    if (len + 1 > cap) {
        return EOVERFLOW;
    }
    memcpy(dst, s, len);
    dst[len] = '\0';
    return 0;
}

static int xcopy_child(const xnode *parent, const char *name, char *dst,
                       size_t cap)
{
    return xcopy(xchild(parent, name), dst, cap);
}

static int add_string(cfn_string_list *list, const xnode *node)
{
    char **grown = realloc(list->items, (list->count + 1) * sizeof(*grown));
    if (grown == NULL) {
        return ENOMEM;
    }
    list->items = grown;
    list->items[list->count] = strdup(node->text != NULL ? node->text : "");
    if (list->items[list->count] == NULL) {
        return ENOMEM;
    }
    list->count++;
    return 0;
}

static void free_string_list(cfn_string_list *list)
{
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

/* ------------------------------------------------------- stack enum tables */

static const char *const STACK_STATUS_NAMES[] = {
    [CFN_STACK_STATUS_UNKNOWN] = "UNKNOWN",
    [CFN_STACK_STATUS_CREATE_IN_PROGRESS] = "CREATE_IN_PROGRESS",
    [CFN_STACK_STATUS_CREATE_FAILED] = "CREATE_FAILED",
    [CFN_STACK_STATUS_CREATE_COMPLETE] = "CREATE_COMPLETE",
    [CFN_STACK_STATUS_ROLLBACK_IN_PROGRESS] = "ROLLBACK_IN_PROGRESS",
    [CFN_STACK_STATUS_ROLLBACK_FAILED] = "ROLLBACK_FAILED",
    [CFN_STACK_STATUS_ROLLBACK_COMPLETE] = "ROLLBACK_COMPLETE",
    [CFN_STACK_STATUS_DELETE_IN_PROGRESS] = "DELETE_IN_PROGRESS",
    [CFN_STACK_STATUS_DELETE_FAILED] = "DELETE_FAILED",
    [CFN_STACK_STATUS_DELETE_COMPLETE] = "DELETE_COMPLETE",
    [CFN_STACK_STATUS_UPDATE_IN_PROGRESS] = "UPDATE_IN_PROGRESS",
    [CFN_STACK_STATUS_UPDATE_COMPLETE_CLEANUP_IN_PROGRESS] =
        "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
    [CFN_STACK_STATUS_UPDATE_COMPLETE] = "UPDATE_COMPLETE",
    [CFN_STACK_STATUS_UPDATE_FAILED] = "UPDATE_FAILED",
    [CFN_STACK_STATUS_UPDATE_ROLLBACK_IN_PROGRESS] =
        "UPDATE_ROLLBACK_IN_PROGRESS",
    [CFN_STACK_STATUS_UPDATE_ROLLBACK_FAILED] = "UPDATE_ROLLBACK_FAILED",
    [CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS] =
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
    [CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE] =
        "UPDATE_ROLLBACK_COMPLETE",
    [CFN_STACK_STATUS_REVIEW_IN_PROGRESS] = "REVIEW_IN_PROGRESS",
    [CFN_STACK_STATUS_IMPORT_IN_PROGRESS] = "IMPORT_IN_PROGRESS",
    [CFN_STACK_STATUS_IMPORT_COMPLETE] = "IMPORT_COMPLETE",
    [CFN_STACK_STATUS_IMPORT_ROLLBACK_IN_PROGRESS] =
        "IMPORT_ROLLBACK_IN_PROGRESS",
    [CFN_STACK_STATUS_IMPORT_ROLLBACK_FAILED] = "IMPORT_ROLLBACK_FAILED",
    [CFN_STACK_STATUS_IMPORT_ROLLBACK_COMPLETE] =
        "IMPORT_ROLLBACK_COMPLETE",
};

const char *cfn_stack_status_string(cfn_stack_status status)
{
    if (status < 0 ||
        (size_t)status >= sizeof(STACK_STATUS_NAMES) / sizeof(STACK_STATUS_NAMES[0])) {
        return STACK_STATUS_NAMES[CFN_STACK_STATUS_UNKNOWN];
    }
    return STACK_STATUS_NAMES[status] != NULL ? STACK_STATUS_NAMES[status]
                                              : STACK_STATUS_NAMES[CFN_STACK_STATUS_UNKNOWN];
}

int cfn_stack_status_parse(const char *name, cfn_stack_status *out)
{
    if (name == NULL || out == NULL) {
        return EINVAL;
    }
    *out = CFN_STACK_STATUS_UNKNOWN;
    for (size_t i = 0; i < sizeof(STACK_STATUS_NAMES) / sizeof(STACK_STATUS_NAMES[0]);
         i++) {
        if (STACK_STATUS_NAMES[i] != NULL && strcmp(STACK_STATUS_NAMES[i], name) == 0) {
            *out = (cfn_stack_status)i;
            return 0;
        }
    }
    return 0;
}

int cfn_stack_status_is_in_progress(cfn_stack_status status)
{
    switch (status) {
    case CFN_STACK_STATUS_CREATE_IN_PROGRESS:
    case CFN_STACK_STATUS_ROLLBACK_IN_PROGRESS:
    case CFN_STACK_STATUS_DELETE_IN_PROGRESS:
    case CFN_STACK_STATUS_UPDATE_IN_PROGRESS:
    case CFN_STACK_STATUS_UPDATE_COMPLETE_CLEANUP_IN_PROGRESS:
    case CFN_STACK_STATUS_UPDATE_ROLLBACK_IN_PROGRESS:
    case CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS:
    case CFN_STACK_STATUS_IMPORT_IN_PROGRESS:
    case CFN_STACK_STATUS_IMPORT_ROLLBACK_IN_PROGRESS:
        return 1;
    default:
        return 0;
    }
}

int cfn_stack_status_is_healthy(cfn_stack_status status)
{
    return status == CFN_STACK_STATUS_CREATE_COMPLETE ||
           status == CFN_STACK_STATUS_UPDATE_COMPLETE ||
           status == CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE;
}

static const char *const CHANGE_SET_STATUS_NAMES[] = {
    [CFN_CHANGE_SET_STATUS_UNKNOWN] = "UNKNOWN",
    [CFN_CHANGE_SET_STATUS_CREATE_PENDING] = "CREATE_PENDING",
    [CFN_CHANGE_SET_STATUS_CREATE_IN_PROGRESS] = "CREATE_IN_PROGRESS",
    [CFN_CHANGE_SET_STATUS_CREATE_COMPLETE] = "CREATE_COMPLETE",
    [CFN_CHANGE_SET_STATUS_DELETE_PENDING] = "DELETE_PENDING",
    [CFN_CHANGE_SET_STATUS_DELETE_IN_PROGRESS] = "DELETE_IN_PROGRESS",
    [CFN_CHANGE_SET_STATUS_DELETE_COMPLETE] = "DELETE_COMPLETE",
    [CFN_CHANGE_SET_STATUS_DELETE_FAILED] = "DELETE_FAILED",
    [CFN_CHANGE_SET_STATUS_FAILED] = "FAILED",
};

const char *cfn_change_set_status_string(cfn_change_set_status status)
{
    if (status < 0 ||
        (size_t)status >=
            sizeof(CHANGE_SET_STATUS_NAMES) / sizeof(CHANGE_SET_STATUS_NAMES[0])) {
        return CHANGE_SET_STATUS_NAMES[CFN_CHANGE_SET_STATUS_UNKNOWN];
    }
    return CHANGE_SET_STATUS_NAMES[status] != NULL
               ? CHANGE_SET_STATUS_NAMES[status]
               : CHANGE_SET_STATUS_NAMES[CFN_CHANGE_SET_STATUS_UNKNOWN];
}

int cfn_change_set_status_parse(const char *name, cfn_change_set_status *out)
{
    if (name == NULL || out == NULL) {
        return EINVAL;
    }
    *out = CFN_CHANGE_SET_STATUS_UNKNOWN;
    for (size_t i = 0;
         i < sizeof(CHANGE_SET_STATUS_NAMES) / sizeof(CHANGE_SET_STATUS_NAMES[0]);
         i++) {
        if (CHANGE_SET_STATUS_NAMES[i] != NULL &&
            strcmp(CHANGE_SET_STATUS_NAMES[i], name) == 0) {
            *out = (cfn_change_set_status)i;
            return 0;
        }
    }
    return 0;
}

static const char *const EXECUTION_STATUS_NAMES[] = {
    [CFN_CHANGE_SET_EXECUTION_UNKNOWN] = "UNKNOWN",
    [CFN_CHANGE_SET_EXECUTION_UNAVAILABLE] = "UNAVAILABLE",
    [CFN_CHANGE_SET_EXECUTION_AVAILABLE] = "AVAILABLE",
    [CFN_CHANGE_SET_EXECUTION_IN_PROGRESS] = "EXECUTE_IN_PROGRESS",
    [CFN_CHANGE_SET_EXECUTION_COMPLETE] = "EXECUTE_COMPLETE",
    [CFN_CHANGE_SET_EXECUTION_FAILED] = "EXECUTE_FAILED",
    [CFN_CHANGE_SET_EXECUTION_OBSOLETE] = "OBSOLETE",
};

const char *cfn_change_set_execution_status_string(
    cfn_change_set_execution_status status)
{
    if (status < 0 ||
        (size_t)status >=
            sizeof(EXECUTION_STATUS_NAMES) / sizeof(EXECUTION_STATUS_NAMES[0])) {
        return EXECUTION_STATUS_NAMES[CFN_CHANGE_SET_EXECUTION_UNKNOWN];
    }
    return EXECUTION_STATUS_NAMES[status] != NULL
               ? EXECUTION_STATUS_NAMES[status]
               : EXECUTION_STATUS_NAMES[CFN_CHANGE_SET_EXECUTION_UNKNOWN];
}

int cfn_change_set_execution_status_parse(
    const char *name, cfn_change_set_execution_status *out)
{
    if (name == NULL || out == NULL) {
        return EINVAL;
    }
    *out = CFN_CHANGE_SET_EXECUTION_UNKNOWN;
    for (size_t i = 0;
         i < sizeof(EXECUTION_STATUS_NAMES) / sizeof(EXECUTION_STATUS_NAMES[0]);
         i++) {
        if (EXECUTION_STATUS_NAMES[i] != NULL &&
            strcmp(EXECUTION_STATUS_NAMES[i], name) == 0) {
            *out = (cfn_change_set_execution_status)i;
            return 0;
        }
    }
    return 0;
}

/* --------------------------------------------------------- request helpers */

static int hex_digit(unsigned char c)
{
    return isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
}

static int sb_put_encoded(sbuf *b, const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        if (hex_digit(*p)) {
            if (sb_putc(b, (char)*p) != 0) {
                return ENOMEM;
            }
        } else {
            char esc[3] = {'%', hex[*p >> 4], hex[*p & 0x0f]};
            if (sb_putn(b, esc, sizeof(esc)) != 0) {
                return ENOMEM;
            }
        }
    }
    return 0;
}

static int form_add(sbuf *form, const char *key, const char *value)
{
    if (form->len > 0 && sb_putc(form, '&') != 0) {
        return ENOMEM;
    }
    if (sb_put_encoded(form, key) != 0 || sb_putc(form, '=') != 0 ||
        sb_put_encoded(form, value) != 0) {
        return ENOMEM;
    }
    return 0;
}

static int form_addf(sbuf *form, const char *value, const char *fmt, ...)
{
    char key[160];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(key, sizeof(key), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(key)) {
        return EINVAL;
    }
    return form_add(form, key, value);
}

static int form_begin(sbuf *form, const char *action)
{
    if (form_add(form, "Action", action) != 0 ||
        form_add(form, "Version", CFN_API_VERSION) != 0) {
        return ENOMEM;
    }
    return 0;
}

static int default_send(aws_ctx *ctx, const aws_req *req, aws_resp *resp,
                        void *ud)
{
    (void)ud;
    return aws_request(ctx, req, resp);
}

static int client_alloc(cfn_client **out, aws_ctx *aws, cfn_transport_fn send,
                        void *ud)
{
    if (out == NULL || send == NULL) {
        return EINVAL;
    }
    cfn_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return ENOMEM;
    }
    client->aws = aws;
    client->send = send;
    client->ud = ud;
    *out = client;
    return 0;
}

int cfn_client_create(cfn_client **out, aws_ctx *aws)
{
    if (aws == NULL) {
        return EINVAL;
    }
    return client_alloc(out, aws, default_send, NULL);
}

int cfn_client_create_with_transport(cfn_client **out, aws_ctx *aws,
                                     cfn_transport_fn send, void *ud)
{
    return client_alloc(out, aws, send, ud);
}

void cfn_client_destroy(cfn_client *client)
{
    free(client);
}

/* ----------------------------------------------------------- error mapping */

static int map_error_code(const char *code, const char *message)
{
    if (ascii_icontains(message, "does not exist") ||
        ascii_icontains(message, "not exist") ||
        ascii_icontains(code, "NotFound")) {
        return ENOENT;
    }
    if (ascii_icontains(code, "AlreadyExists") ||
        ascii_icontains(message, "already exists")) {
        return EEXIST;
    }
    if (ascii_icontains(message, "No updates are to be performed")) {
        return EALREADY;
    }
    if (ascii_icontains(code, "AccessDenied") ||
        ascii_icontains(code, "Unauthorized")) {
        return EACCES;
    }
    if (ascii_icontains(code, "InsufficientCapabilities") ||
        ascii_icontains(message, "insufficient capabilities")) {
        return EPERM;
    }
    if (ascii_icontains(code, "Throttl")) {
        return EBUSY;
    }
    return EIO;
}

static int fail_from_response(const char *action, aws_resp *resp)
{
    char code[128] = {0};
    char message[1024] = {0};
    xnode *root = NULL;
    if (parse_document(resp->body, &root) == 0) {
        const xnode *error = xchild(root, "Error");
        if (error != NULL) {
            xcopy_child(error, "Code", code, sizeof(code));
            xcopy_child(error, "Message", message, sizeof(message));
        }
    }
    xnode_free(root);
    if (code[0] == '\0') {
        (void)aws_error_code(resp, code);
    }
    if (message[0] == '\0') {
        snprintf(message, sizeof(message), "HTTP %ld", resp->status);
    }
    fprintf(stderr, "stackctl: CloudFormation %s failed: %s: %s\n", action,
            code[0] != '\0' ? code : "Error", message);
    return map_error_code(code, message);
}

static int cfn_call(cfn_client *client, const char *region, const char *action,
                    sbuf *form, aws_resp *resp)
{
    if (client == NULL || region == NULL || action == NULL || form == NULL ||
        resp == NULL) {
        return EINVAL;
    }
    aws_req req = {
        .service = "cloudformation",
        .region = region,
        .method = "POST",
        .path = "/",
        .query = NULL,
        .body = form->data,
        .body_len = form->len,
        .content_type = CFN_CONTENT_TYPE,
        .unsigned_payload = 0,
    };
    memset(resp, 0, sizeof(*resp));
    int rc = client->send(client->aws, &req, resp, client->ud);
    if (rc != 0) {
        return rc;
    }
    if (resp->status >= 200 && resp->status < 300) {
        return 0;
    }
    int mapped = fail_from_response(action, resp);
    aws_resp_free(resp);
    return mapped;
}

/* -------------------------------------------------------- response parsing */

static int grow_array(void **items, size_t count, size_t elem_size)
{
    void *grown = realloc(*items, (count + 1) * elem_size);
    if (grown == NULL) {
        return ENOMEM;
    }
    *items = grown;
    return 0;
}

static void stack_release(cfn_stack *stack)
{
    free(stack->parameters);
    free(stack->outputs);
    free(stack->tags);
    stack->parameters = NULL;
    stack->outputs = NULL;
    stack->tags = NULL;
    stack->parameter_count = 0;
    stack->output_count = 0;
    stack->tag_count = 0;
}

static void stack_list_release(cfn_stack_list *list)
{
    for (size_t i = 0; i < list->count; i++) {
        stack_release(&list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

void cfn_stack_list_free(cfn_stack_list *list)
{
    if (list != NULL) {
        stack_list_release(list);
    }
}

static int parse_parameters(const xnode *parent, cfn_parameter **items,
                            size_t *count)
{
    const xnode *container = xchild(parent, "Parameters");
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        cfn_parameter param = {0};
        int rc = xcopy_child(member, "ParameterKey", param.key, sizeof(param.key));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "ParameterValue", param.value,
                         sizeof(param.value));
        if (rc != 0) {
            return rc;
        }
        rc = grow_array((void **)items, *count, sizeof(**items));
        if (rc != 0) {
            return rc;
        }
        (*items)[*count] = param;
        (*count)++;
    }
    return 0;
}

static int parse_outputs(const xnode *parent, cfn_output **items, size_t *count)
{
    const xnode *container = xchild(parent, "Outputs");
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        cfn_output output = {0};
        int rc = xcopy_child(member, "OutputKey", output.key, sizeof(output.key));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "OutputValue", output.value,
                         sizeof(output.value));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "Description", output.description,
                         sizeof(output.description));
        if (rc != 0) {
            return rc;
        }
        rc = grow_array((void **)items, *count, sizeof(**items));
        if (rc != 0) {
            return rc;
        }
        (*items)[*count] = output;
        (*count)++;
    }
    return 0;
}

static int parse_tags(const xnode *parent, cfn_tag **items, size_t *count)
{
    const xnode *container = xchild(parent, "Tags");
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        cfn_tag tag = {0};
        int rc = xcopy_child(member, "Key", tag.key, sizeof(tag.key));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "Value", tag.value, sizeof(tag.value));
        if (rc != 0) {
            return rc;
        }
        rc = grow_array((void **)items, *count, sizeof(**items));
        if (rc != 0) {
            return rc;
        }
        (*items)[*count] = tag;
        (*count)++;
    }
    return 0;
}

static int parse_stack(const xnode *member, cfn_stack *stack)
{
    memset(stack, 0, sizeof(*stack));
    int rc = xcopy_child(member, "StackName", stack->stack_name,
                         sizeof(stack->stack_name));
    if (rc != 0) {
        return rc;
    }
    if (stack->stack_name[0] == '\0') {
        return EPROTO;
    }
    rc = xcopy_child(member, "StackId", stack->stack_id, sizeof(stack->stack_id));
    if (rc != 0) {
        return rc;
    }
    char status[64] = {0};
    rc = xcopy_child(member, "StackStatus", status, sizeof(status));
    if (rc != 0) {
        return rc;
    }
    (void)cfn_stack_status_parse(status, &stack->status);
    rc = xcopy_child(member, "StackStatusReason", stack->status_reason,
                     sizeof(stack->status_reason));
    if (rc != 0) {
        return rc;
    }
    rc = parse_parameters(member, &stack->parameters, &stack->parameter_count);
    if (rc != 0) {
        return rc;
    }
    rc = parse_outputs(member, &stack->outputs, &stack->output_count);
    if (rc != 0) {
        return rc;
    }
    return parse_tags(member, &stack->tags, &stack->tag_count);
}

const char *cfn_stack_output(const cfn_stack *stack, const char *key)
{
    if (stack == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < stack->output_count; i++) {
        if (strcmp(stack->outputs[i].key, key) == 0) {
            return stack->outputs[i].value;
        }
    }
    return NULL;
}

const char *cfn_stack_parameter(const cfn_stack *stack, const char *key)
{
    if (stack == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < stack->parameter_count; i++) {
        if (strcmp(stack->parameters[i].key, key) == 0) {
            return stack->parameters[i].value;
        }
    }
    return NULL;
}

const char *cfn_stack_tag(const cfn_stack *stack, const char *key)
{
    if (stack == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < stack->tag_count; i++) {
        if (strcmp(stack->tags[i].key, key) == 0) {
            return stack->tags[i].value;
        }
    }
    return NULL;
}

/* ------------------------------------------------------- describe stacks */

static int parse_describe_stacks_page(cfn_client *client, const char *region,
                                      sbuf *form, cfn_stack_list *out,
                                      char *next_token, size_t next_cap)
{
    aws_resp resp = {0};
    int rc = cfn_call(client, region, "DescribeStacks", form, &resp);
    if (rc != 0) {
        return rc;
    }
    xnode *root = NULL;
    rc = parse_document(resp.body, &root);
    aws_resp_free(&resp);
    if (rc != 0) {
        return rc;
    }
    const xnode *result = xchild(root, "DescribeStacksResult");
    const xnode *stacks = xchild(result, "Stacks");
    if (result == NULL || stacks == NULL) {
        xnode_free(root);
        return EPROTO;
    }
    for (size_t i = 0; i < stacks->kid_count; i++) {
        cfn_stack stack = {0};
        rc = parse_stack(stacks->kids[i], &stack);
        if (rc != 0) {
            stack_release(&stack);
            xnode_free(root);
            return rc;
        }
        rc = grow_array((void **)&out->items, out->count, sizeof(*out->items));
        if (rc != 0) {
            stack_release(&stack);
            xnode_free(root);
            return rc;
        }
        out->items[out->count++] = stack;
    }
    rc = xcopy_child(result, "NextToken", next_token, next_cap);
    xnode_free(root);
    return rc;
}

int cfn_describe_stacks(cfn_client *client, const char *region,
                        const char *stack_name, cfn_stack_list *out)
{
    if (client == NULL || region == NULL || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    char token[1024] = {0};
    for (int page = 0; page < CFN_MAX_PAGES; page++) {
        sbuf form = {0};
        if (form_begin(&form, "DescribeStacks") != 0 ||
            (stack_name != NULL && form_add(&form, "StackName", stack_name) != 0) ||
            (token[0] != '\0' && form_add(&form, "NextToken", token) != 0)) {
            sb_free(&form);
            stack_list_release(out);
            return ENOMEM;
        }
        int rc = parse_describe_stacks_page(client, region, &form, out, token,
                                            sizeof(token));
        sb_free(&form);
        if (rc != 0) {
            stack_list_release(out);
            return rc;
        }
        if (token[0] == '\0') {
            return 0;
        }
    }
    stack_list_release(out);
    return EOVERFLOW;
}

/* ----------------------------------------------------------- change sets */

static const char *change_set_type_name(cfn_change_set_type type)
{
    return type == CFN_CHANGE_SET_TYPE_CREATE ? "CREATE" : "UPDATE";
}

static int add_capabilities(sbuf *form, unsigned capabilities)
{
    static const struct {
        unsigned flag;
        const char *name;
    } table[] = {
        {CFN_CAPABILITY_IAM, "CAPABILITY_IAM"},
        {CFN_CAPABILITY_NAMED_IAM, "CAPABILITY_NAMED_IAM"},
        {CFN_CAPABILITY_AUTO_EXPAND, "CAPABILITY_AUTO_EXPAND"},
    };
    int index = 0;
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if ((capabilities & table[i].flag) != 0) {
            index++;
            if (form_addf(form, table[i].name, "Capabilities.member.%d", index) != 0) {
                return ENOMEM;
            }
        }
    }
    return 0;
}

int cfn_create_change_set(cfn_client *client, const char *region,
                          const cfn_change_set_spec *spec,
                          cfn_change_set_result *out)
{
    if (client == NULL || region == NULL || spec == NULL || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    if (spec->stack_name == NULL || spec->change_set_name == NULL ||
        spec->template_body == NULL || spec->change_set_name[0] == '\0' ||
        (spec->type != CFN_CHANGE_SET_TYPE_CREATE &&
         spec->type != CFN_CHANGE_SET_TYPE_UPDATE) ||
        (spec->parameter_count > 0 && spec->parameters == NULL) ||
        (spec->tag_count > 0 && spec->tags == NULL)) {
        return EINVAL;
    }

    sbuf form = {0};
    int rc = form_begin(&form, "CreateChangeSet");
    if (rc == 0) {
        rc = form_add(&form, "StackName", spec->stack_name);
    }
    if (rc == 0) {
        rc = form_add(&form, "ChangeSetName", spec->change_set_name);
    }
    if (rc == 0) {
        rc = form_add(&form, "ChangeSetType", change_set_type_name(spec->type));
    }
    if (rc == 0) {
        rc = form_add(&form, "TemplateBody", spec->template_body);
    }
    if (rc == 0 && spec->description != NULL) {
        rc = form_add(&form, "Description", spec->description);
    }
    if (rc == 0) {
        rc = add_capabilities(&form, spec->capabilities);
    }
    for (size_t i = 0; rc == 0 && i < spec->parameter_count; i++) {
        const cfn_parameter *p = &spec->parameters[i];
        if (p->key[0] == '\0') {
            rc = EINVAL;
            break;
        }
        rc = form_addf(&form, p->key, "Parameters.member.%zu.ParameterKey",
                       i + 1);
        if (rc == 0 && p->use_previous_value) {
            rc = form_addf(&form, "true",
                           "Parameters.member.%zu.UsePreviousValue", i + 1);
        } else if (rc == 0) {
            rc = form_addf(&form, p->value,
                           "Parameters.member.%zu.ParameterValue", i + 1);
        }
    }
    for (size_t i = 0; rc == 0 && i < spec->tag_count; i++) {
        const cfn_tag *t = &spec->tags[i];
        if (t->key[0] == '\0') {
            rc = EINVAL;
            break;
        }
        rc = form_addf(&form, t->key, "Tags.member.%zu.Key", i + 1);
        if (rc == 0) {
            rc = form_addf(&form, t->value, "Tags.member.%zu.Value", i + 1);
        }
    }
    if (rc != 0) {
        sb_free(&form);
        return rc;
    }

    aws_resp resp = {0};
    rc = cfn_call(client, region, "CreateChangeSet", &form, &resp);
    sb_free(&form);
    if (rc != 0) {
        return rc;
    }
    xnode *root = NULL;
    rc = parse_document(resp.body, &root);
    aws_resp_free(&resp);
    if (rc != 0) {
        return rc;
    }
    const xnode *result = xchild(root, "CreateChangeSetResult");
    if (result == NULL) {
        xnode_free(root);
        return EPROTO;
    }
    rc = xcopy_child(result, "Id", out->change_set_id,
                     sizeof(out->change_set_id));
    if (rc == 0) {
        rc = xcopy_child(result, "StackId", out->stack_id,
                         sizeof(out->stack_id));
    }
    if (rc == 0 && out->change_set_id[0] == '\0') {
        rc = EPROTO;
    }
    xnode_free(root);
    return rc;
}

void cfn_change_set_free(cfn_change_set *change_set)
{
    if (change_set == NULL) {
        return;
    }
    free(change_set->changes);
    memset(change_set, 0, sizeof(*change_set));
}

static int parse_changes(const xnode *result, cfn_change_set *out)
{
    const xnode *container = xchild(result, "Changes");
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        const xnode *resource = xchild(member, "ResourceChange");
        if (resource == NULL) {
            continue;
        }
        cfn_change change = {0};
        int rc = xcopy_child(resource, "Action", change.action,
                             sizeof(change.action));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(resource, "LogicalResourceId", change.logical_resource_id,
                         sizeof(change.logical_resource_id));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(resource, "PhysicalResourceId",
                         change.physical_resource_id,
                         sizeof(change.physical_resource_id));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(resource, "ResourceType", change.resource_type,
                         sizeof(change.resource_type));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(resource, "Replacement", change.replacement,
                         sizeof(change.replacement));
        if (rc != 0) {
            return rc;
        }
        rc = grow_array((void **)&out->changes, out->change_count,
                        sizeof(*out->changes));
        if (rc != 0) {
            return rc;
        }
        out->changes[out->change_count++] = change;
    }
    return 0;
}

int cfn_describe_change_set(cfn_client *client, const char *region,
                            const char *stack_name, const char *change_set_name,
                            cfn_change_set *out)
{
    if (client == NULL || region == NULL || change_set_name == NULL ||
        change_set_name[0] == '\0' || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    char token[1024] = {0};
    for (int page = 0; page < CFN_MAX_PAGES; page++) {
        sbuf form = {0};
        int rc = form_begin(&form, "DescribeChangeSet");
        if (rc == 0 && stack_name != NULL) {
            rc = form_add(&form, "StackName", stack_name);
        }
        if (rc == 0) {
            rc = form_add(&form, "ChangeSetName", change_set_name);
        }
        if (rc == 0 && token[0] != '\0') {
            rc = form_add(&form, "NextToken", token);
        }
        if (rc != 0) {
            sb_free(&form);
            cfn_change_set_free(out);
            return rc;
        }

        aws_resp resp = {0};
        rc = cfn_call(client, region, "DescribeChangeSet", &form, &resp);
        sb_free(&form);
        if (rc != 0) {
            cfn_change_set_free(out);
            return rc;
        }
        xnode *root = NULL;
        rc = parse_document(resp.body, &root);
        aws_resp_free(&resp);
        if (rc != 0) {
            cfn_change_set_free(out);
            return rc;
        }
        const xnode *result = xchild(root, "DescribeChangeSetResult");
        if (result == NULL) {
            xnode_free(root);
            cfn_change_set_free(out);
            return EPROTO;
        }
        if (page == 0) {
            rc = xcopy_child(result, "ChangeSetId", out->change_set_id,
                             sizeof(out->change_set_id));
            if (rc == 0) {
                rc = xcopy_child(result, "ChangeSetName", out->change_set_name,
                                 sizeof(out->change_set_name));
            }
            if (rc == 0) {
                rc = xcopy_child(result, "StackId", out->stack_id,
                                 sizeof(out->stack_id));
            }
            if (rc == 0) {
                rc = xcopy_child(result, "StackName", out->stack_name,
                                 sizeof(out->stack_name));
            }
            if (rc == 0) {
                rc = xcopy_child(result, "StatusReason", out->status_reason,
                                 sizeof(out->status_reason));
            }
            char status[64] = {0};
            if (rc == 0) {
                rc = xcopy_child(result, "Status", status, sizeof(status));
            }
            if (rc == 0) {
                (void)cfn_change_set_status_parse(status, &out->status);
            }
            char execution[64] = {0};
            if (rc == 0) {
                rc = xcopy_child(result, "ExecutionStatus", execution,
                                 sizeof(execution));
            }
            if (rc == 0) {
                (void)cfn_change_set_execution_status_parse(
                    execution, &out->execution_status);
            }
        }
        if (rc == 0) {
            rc = parse_changes(result, out);
        }
        if (rc == 0) {
            rc = xcopy_child(result, "NextToken", token, sizeof(token));
        }
        xnode_free(root);
        if (rc != 0) {
            cfn_change_set_free(out);
            return rc;
        }
        if (token[0] == '\0') {
            return 0;
        }
    }
    cfn_change_set_free(out);
    return EOVERFLOW;
}

static int simple_change_set_call(cfn_client *client, const char *region,
                                  const char *action, const char *stack_name,
                                  const char *change_set_name,
                                  int absent_is_ok)
{
    if (client == NULL || region == NULL || change_set_name == NULL ||
        change_set_name[0] == '\0') {
        return EINVAL;
    }
    sbuf form = {0};
    int rc = form_begin(&form, action);
    if (rc == 0 && stack_name != NULL) {
        rc = form_add(&form, "StackName", stack_name);
    }
    if (rc == 0) {
        rc = form_add(&form, "ChangeSetName", change_set_name);
    }
    if (rc != 0) {
        sb_free(&form);
        return rc;
    }
    aws_resp resp = {0};
    rc = cfn_call(client, region, action, &form, &resp);
    sb_free(&form);
    aws_resp_free(&resp);
    if (absent_is_ok && rc == ENOENT) {
        return 0;
    }
    return rc;
}

int cfn_execute_change_set(cfn_client *client, const char *region,
                           const char *stack_name, const char *change_set_name)
{
    return simple_change_set_call(client, region, "ExecuteChangeSet", stack_name,
                                  change_set_name, 0);
}

int cfn_delete_change_set(cfn_client *client, const char *region,
                          const char *stack_name, const char *change_set_name)
{
    return simple_change_set_call(client, region, "DeleteChangeSet", stack_name,
                                  change_set_name, 1);
}

/* ------------------------------------------------------ template summary */

void cfn_template_summary_free(cfn_template_summary *summary)
{
    if (summary == NULL) {
        return;
    }
    free(summary->parameters);
    free_string_list(&summary->capabilities);
    free_string_list(&summary->resource_types);
    memset(summary, 0, sizeof(*summary));
}

static int parse_template_parameters(const xnode *result,
                                     cfn_template_summary *out)
{
    const xnode *container = xchild(result, "Parameters");
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        cfn_template_parameter param = {0};
        int rc = xcopy_child(member, "ParameterKey", param.key,
                             sizeof(param.key));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "DefaultValue", param.default_value,
                         sizeof(param.default_value));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "ParameterType", param.parameter_type,
                         sizeof(param.parameter_type));
        if (rc != 0) {
            return rc;
        }
        rc = xcopy_child(member, "Description", param.description,
                         sizeof(param.description));
        if (rc != 0) {
            return rc;
        }
        char no_echo[16] = {0};
        rc = xcopy_child(member, "NoEcho", no_echo, sizeof(no_echo));
        if (rc != 0) {
            return rc;
        }
        param.no_echo = ascii_ieq(no_echo, "true") ? 1 : 0;
        rc = grow_array((void **)&out->parameters, out->parameter_count,
                        sizeof(*out->parameters));
        if (rc != 0) {
            return rc;
        }
        out->parameters[out->parameter_count++] = param;
    }
    return 0;
}

static int parse_string_members(const xnode *result, const char *container_name,
                                cfn_string_list *list)
{
    const xnode *container = xchild(result, container_name);
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        int rc = add_string(list, container->kids[i]);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int cfn_get_template_summary(cfn_client *client, const char *region,
                             const char *template_body,
                             cfn_template_summary *out)
{
    if (client == NULL || region == NULL || template_body == NULL || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    sbuf form = {0};
    int rc = form_begin(&form, "GetTemplateSummary");
    if (rc == 0) {
        rc = form_add(&form, "TemplateBody", template_body);
    }
    if (rc != 0) {
        sb_free(&form);
        return rc;
    }
    aws_resp resp = {0};
    rc = cfn_call(client, region, "GetTemplateSummary", &form, &resp);
    sb_free(&form);
    if (rc != 0) {
        return rc;
    }
    xnode *root = NULL;
    rc = parse_document(resp.body, &root);
    aws_resp_free(&resp);
    if (rc != 0) {
        return rc;
    }
    const xnode *result = xchild(root, "GetTemplateSummaryResult");
    if (result == NULL) {
        xnode_free(root);
        return EPROTO;
    }
    rc = parse_template_parameters(result, out);
    if (rc == 0) {
        rc = parse_string_members(result, "Capabilities", &out->capabilities);
    }
    if (rc == 0) {
        rc = parse_string_members(result, "ResourceTypes", &out->resource_types);
    }
    if (rc == 0) {
        rc = xcopy_child(result, "Description", out->description,
                         sizeof(out->description));
    }
    xnode_free(root);
    if (rc != 0) {
        cfn_template_summary_free(out);
    }
    return rc;
}

/* ------------------------------------------------------------- operations */

int cfn_delete_stack(cfn_client *client, const char *region,
                     const char *stack_name)
{
    if (client == NULL || region == NULL || stack_name == NULL) {
        return EINVAL;
    }
    sbuf form = {0};
    int rc = form_begin(&form, "DeleteStack");
    if (rc == 0) {
        rc = form_add(&form, "StackName", stack_name);
    }
    if (rc != 0) {
        sb_free(&form);
        return rc;
    }
    aws_resp resp = {0};
    rc = cfn_call(client, region, "DeleteStack", &form, &resp);
    sb_free(&form);
    aws_resp_free(&resp);
    return rc == ENOENT ? 0 : rc;
}

void cfn_stack_resource_list_free(cfn_stack_resource_list *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

int cfn_describe_stack_resources(cfn_client *client, const char *region,
                                 const char *stack_name,
                                 cfn_stack_resource_list *out)
{
    if (client == NULL || region == NULL || stack_name == NULL || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    sbuf form = {0};
    int rc = form_begin(&form, "DescribeStackResources");
    if (rc == 0) {
        rc = form_add(&form, "StackName", stack_name);
    }
    if (rc != 0) {
        sb_free(&form);
        return rc;
    }
    aws_resp resp = {0};
    rc = cfn_call(client, region, "DescribeStackResources", &form, &resp);
    sb_free(&form);
    if (rc != 0) {
        return rc;
    }
    xnode *root = NULL;
    rc = parse_document(resp.body, &root);
    aws_resp_free(&resp);
    if (rc != 0) {
        return rc;
    }
    const xnode *result = xchild(root, "DescribeStackResourcesResult");
    const xnode *container = xchild(result, "StackResources");
    if (result == NULL || container == NULL) {
        xnode_free(root);
        return EPROTO;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        cfn_stack_resource resource = {0};
        rc = xcopy_child(member, "LogicalResourceId", resource.logical_resource_id,
                         sizeof(resource.logical_resource_id));
        if (rc == 0) {
            rc = xcopy_child(member, "PhysicalResourceId",
                             resource.physical_resource_id,
                             sizeof(resource.physical_resource_id));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "ResourceType", resource.resource_type,
                             sizeof(resource.resource_type));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "ResourceStatus", resource.resource_status,
                             sizeof(resource.resource_status));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "ResourceStatusReason",
                             resource.resource_status_reason,
                             sizeof(resource.resource_status_reason));
        }
        if (rc == 0) {
            rc = grow_array((void **)&out->items, out->count,
                            sizeof(*out->items));
        }
        if (rc != 0) {
            xnode_free(root);
            cfn_stack_resource_list_free(out);
            return rc;
        }
        out->items[out->count++] = resource;
    }
    xnode_free(root);
    return 0;
}

void cfn_event_list_free(cfn_event_list *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static int parse_events(const xnode *result, cfn_event_list *out)
{
    const xnode *container = xchild(result, "StackEvents");
    if (container == NULL) {
        return 0;
    }
    for (size_t i = 0; i < container->kid_count; i++) {
        const xnode *member = container->kids[i];
        cfn_event event = {0};
        int rc = xcopy_child(member, "EventId", event.event_id,
                             sizeof(event.event_id));
        if (rc == 0) {
            rc = xcopy_child(member, "Timestamp", event.timestamp,
                             sizeof(event.timestamp));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "LogicalResourceId",
                             event.logical_resource_id,
                             sizeof(event.logical_resource_id));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "PhysicalResourceId",
                             event.physical_resource_id,
                             sizeof(event.physical_resource_id));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "ResourceType", event.resource_type,
                             sizeof(event.resource_type));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "ResourceStatus", event.resource_status,
                             sizeof(event.resource_status));
        }
        if (rc == 0) {
            rc = xcopy_child(member, "ResourceStatusReason",
                             event.resource_status_reason,
                             sizeof(event.resource_status_reason));
        }
        if (rc == 0) {
            rc = grow_array((void **)&out->items, out->count,
                            sizeof(*out->items));
        }
        if (rc != 0) {
            return rc;
        }
        out->items[out->count++] = event;
    }
    return 0;
}

int cfn_describe_stack_events(cfn_client *client, const char *region,
                              const char *stack_name, size_t max_events,
                              cfn_event_list *out)
{
    if (client == NULL || region == NULL || stack_name == NULL || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    char token[1024] = {0};
    for (int page = 0; page < CFN_MAX_PAGES; page++) {
        sbuf form = {0};
        int rc = form_begin(&form, "DescribeStackEvents");
        if (rc == 0) {
            rc = form_add(&form, "StackName", stack_name);
        }
        if (rc == 0 && token[0] != '\0') {
            rc = form_add(&form, "NextToken", token);
        }
        if (rc != 0) {
            sb_free(&form);
            cfn_event_list_free(out);
            return rc;
        }
        aws_resp resp = {0};
        rc = cfn_call(client, region, "DescribeStackEvents", &form, &resp);
        sb_free(&form);
        if (rc != 0) {
            cfn_event_list_free(out);
            return rc;
        }
        xnode *root = NULL;
        rc = parse_document(resp.body, &root);
        aws_resp_free(&resp);
        if (rc != 0) {
            cfn_event_list_free(out);
            return rc;
        }
        const xnode *result = xchild(root, "DescribeStackEventsResult");
        if (result == NULL) {
            xnode_free(root);
            cfn_event_list_free(out);
            return EPROTO;
        }
        rc = parse_events(result, out);
        if (rc == 0) {
            rc = xcopy_child(result, "NextToken", token, sizeof(token));
        }
        xnode_free(root);
        if (rc != 0) {
            cfn_event_list_free(out);
            return rc;
        }
        if (max_events > 0 && out->count >= max_events) {
            break;
        }
        if (token[0] == '\0') {
            break;
        }
    }
    if (max_events > 0 && out->count > max_events) {
        out->count = max_events;
    }
    return 0;
}

/* ---------------------------------------------------------------- waiters */

static int stack_operation_verdict(cfn_wait_operation operation,
                                   cfn_stack_status status, int *success,
                                   int *failure)
{
    *success = 0;
    *failure = 0;
    switch (operation) {
    case CFN_WAIT_CREATE:
        if (status == CFN_STACK_STATUS_CREATE_COMPLETE) {
            *success = 1;
        } else if (status == CFN_STACK_STATUS_CREATE_FAILED ||
                   status == CFN_STACK_STATUS_ROLLBACK_COMPLETE ||
                   status == CFN_STACK_STATUS_ROLLBACK_FAILED ||
                   status == CFN_STACK_STATUS_DELETE_COMPLETE) {
            *failure = 1;
        }
        return 0;
    case CFN_WAIT_UPDATE:
        if (status == CFN_STACK_STATUS_UPDATE_COMPLETE) {
            *success = 1;
        } else if (status == CFN_STACK_STATUS_UPDATE_FAILED ||
                   status == CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE ||
                   status == CFN_STACK_STATUS_UPDATE_ROLLBACK_FAILED ||
                   status == CFN_STACK_STATUS_DELETE_COMPLETE) {
            *failure = 1;
        }
        return 0;
    case CFN_WAIT_DELETE:
        if (status == CFN_STACK_STATUS_DELETE_COMPLETE) {
            *success = 1;
        } else if (status == CFN_STACK_STATUS_DELETE_FAILED ||
                   status == CFN_STACK_STATUS_ROLLBACK_FAILED) {
            *failure = 1;
        }
        return 0;
    default:
        return EINVAL;
    }
}

typedef struct stack_wait_ctx {
    cfn_client *client;
    const char *region;
    const char *stack_name;
    cfn_wait_operation operation;
    int failed;
} stack_wait_ctx;

static int stack_wait_poll(aws_ctx *aws, void *ud, int *done)
{
    (void)aws;
    stack_wait_ctx *ctx = ud;
    cfn_stack_list list = {0};
    int rc = cfn_describe_stacks(ctx->client, ctx->region, ctx->stack_name,
                                 &list);
    if (rc != 0) {
        if (rc == ENOENT && ctx->operation == CFN_WAIT_DELETE) {
            *done = 1;
            return 0;
        }
        return rc;
    }
    if (list.count == 0) {
        cfn_stack_list_free(&list);
        if (ctx->operation == CFN_WAIT_DELETE) {
            *done = 1;
            return 0;
        }
        return ENOENT;
    }
    cfn_stack_status status = list.items[0].status;
    char reason[CFN_STATUS_REASON_MAX];
    snprintf(reason, sizeof(reason), "%s", list.items[0].status_reason);
    cfn_stack_list_free(&list);

    int success = 0;
    int failure = 0;
    rc = stack_operation_verdict(ctx->operation, status, &success, &failure);
    if (rc != 0) {
        return rc;
    }
    if (success) {
        *done = 1;
        return 0;
    }
    if (failure) {
        ctx->failed = 1;
        *done = 1;
        fprintf(stderr,
                "stackctl: stack %s reached %s: %s\n", ctx->stack_name,
                cfn_stack_status_string(status),
                reason[0] != '\0' ? reason : "(no reason reported)");
        return 0;
    }
    return 0;
}

int cfn_wait_for_stack(cfn_client *client, const char *region,
                       const char *stack_name, cfn_wait_operation operation,
                       int attempts, int interval_sec, int *timed_out)
{
    if (client == NULL || region == NULL || stack_name == NULL ||
        timed_out == NULL || attempts < 1 ||
        (operation != CFN_WAIT_CREATE && operation != CFN_WAIT_UPDATE &&
         operation != CFN_WAIT_DELETE)) {
        return EINVAL;
    }
    stack_wait_ctx ctx = {
        .client = client,
        .region = region,
        .stack_name = stack_name,
        .operation = operation,
        .failed = 0,
    };
    int rc = aws_wait(client->aws, stack_wait_poll, &ctx, attempts, interval_sec,
                      timed_out);
    if (rc != 0) {
        return rc;
    }
    return ctx.failed ? ECANCELED : 0;
}

typedef struct change_set_wait_ctx {
    cfn_client *client;
    const char *region;
    const char *stack_name;
    const char *change_set_name;
    int track_no_changes;
    int failed;
    int no_changes;
} change_set_wait_ctx;

/* AWS's fixed StatusReason when the submitted template and parameters make no
 * changes to the stack. Matched as a substring because the message carries an
 * appended instruction sentence. */
static const char NO_CHANGES_REASON[] =
    "didn't contain changes";

static int change_set_wait_poll(aws_ctx *aws, void *ud, int *done)
{
    (void)aws;
    change_set_wait_ctx *ctx = ud;
    cfn_change_set cs = {0};
    int rc = cfn_describe_change_set(ctx->client, ctx->region, ctx->stack_name,
                                     ctx->change_set_name, &cs);
    if (rc != 0) {
        return rc;
    }
    if (cs.status == CFN_CHANGE_SET_STATUS_CREATE_COMPLETE) {
        *done = 1;
    } else if (cs.status == CFN_CHANGE_SET_STATUS_FAILED) {
        if (ctx->track_no_changes != 0 &&
            strstr(cs.status_reason, NO_CHANGES_REASON) != NULL) {
            ctx->no_changes = 1;
            *done = 1;
            fprintf(stderr,
                    "stackctl: change set %s: no changes needed "
                    "(stack already conforms)\n",
                    ctx->change_set_name);
        } else {
            ctx->failed = 1;
            *done = 1;
            fprintf(stderr,
                    "stackctl: change set %s reached %s: %s\n",
                    ctx->change_set_name,
                    cfn_change_set_status_string(cs.status),
                    cs.status_reason[0] != '\0' ? cs.status_reason
                                                : "(no reason reported)");
        }
    } else if (cs.status == CFN_CHANGE_SET_STATUS_DELETE_COMPLETE ||
               cs.status == CFN_CHANGE_SET_STATUS_DELETE_FAILED) {
        ctx->failed = 1;
        *done = 1;
        fprintf(stderr,
                "stackctl: change set %s reached %s: %s\n", ctx->change_set_name,
                cfn_change_set_status_string(cs.status),
                cs.status_reason[0] != '\0' ? cs.status_reason
                                            : "(no reason reported)");
    }
    cfn_change_set_free(&cs);
    return 0;
}

int cfn_wait_for_change_set(cfn_client *client, const char *region,
                            const char *stack_name, const char *change_set_name,
                            int attempts, int interval_sec, int *timed_out,
                            int *no_changes)
{
    if (client == NULL || region == NULL || change_set_name == NULL ||
        timed_out == NULL || attempts < 1) {
        return EINVAL;
    }
    if (no_changes != NULL) {
        *no_changes = 0;
    }
    change_set_wait_ctx ctx = {
        .client = client,
        .region = region,
        .stack_name = stack_name,
        .change_set_name = change_set_name,
        .track_no_changes = no_changes != NULL,
        .failed = 0,
        .no_changes = 0,
    };
    int rc = aws_wait(client->aws, change_set_wait_poll, &ctx, attempts,
                      interval_sec, timed_out);
    if (rc != 0) {
        return rc;
    }
    if (no_changes != NULL) {
        *no_changes = ctx.no_changes;
    }
    return ctx.failed ? ECANCELED : 0;
}
