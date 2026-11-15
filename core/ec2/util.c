/*
 * util.c — EC2 Query encoding and XML/base64 response helpers.
 *
 * The EC2 Query protocol sends every request as a form-encoded POST body and
 * answers with XML. These helpers are deliberately small and allocation-light:
 * a growable body builder, RFC 3986 percent-encoding, a depth-aware element
 * scanner (EC2 responses repeat `<item>` at several nesting levels), entity
 * decoding and base64 decoding for GetConsoleOutput.
 */

#include "ec2_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Percent-encoding                                                          */
/* ------------------------------------------------------------------------- */

static int is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
           c == '~';
}

int ec2_percent_encode(const char *value, char **out)
{
    static const char hex[] = "0123456789ABCDEF";

    if (value == NULL || out == NULL) {
        return EINVAL;
    }

    size_t length = strlen(value);
    char *encoded = malloc(length * 3 + 1);
    if (encoded == NULL) {
        return ENOMEM;
    }

    size_t position = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)value[i];
        if (is_unreserved(byte)) {
            encoded[position++] = (char)byte;
            continue;
        }
        encoded[position++] = '%';
        encoded[position++] = hex[byte >> 4];
        encoded[position++] = hex[byte & 0x0f];
    }
    encoded[position] = '\0';

    *out = encoded;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Form body builder                                                         */
/* ------------------------------------------------------------------------- */

void ec2_params_init(ec2_params *params)
{
    if (params == NULL) {
        return;
    }
    memset(params, 0, sizeof(*params));
}

void ec2_params_free(ec2_params *params)
{
    if (params == NULL) {
        return;
    }
    free(params->body);
    memset(params, 0, sizeof(*params));
}

static int params_reserve(ec2_params *params, size_t extra)
{
    if (params->oom) {
        return ENOMEM;
    }
    if (params->length + extra + 1 <= params->capacity) {
        return 0;
    }

    size_t capacity = params->capacity == 0 ? 256 : params->capacity;
    while (capacity < params->length + extra + 1) {
        capacity *= 2;
    }

    char *grown = realloc(params->body, capacity);
    if (grown == NULL) {
        params->oom = 1;
        return ENOMEM;
    }
    params->body = grown;
    params->capacity = capacity;
    return 0;
}

static int params_append(ec2_params *params, const char *text, size_t length)
{
    int rc = params_reserve(params, length);
    if (rc != 0) {
        return rc;
    }
    memcpy(params->body + params->length, text, length);
    params->length += length;
    params->body[params->length] = '\0';
    return 0;
}

int ec2_params_add(ec2_params *params, const char *name, const char *value)
{
    if (params == NULL || name == NULL || value == NULL) {
        return EINVAL;
    }
    if (params->oom) {
        return ENOMEM;
    }

    char *encoded = NULL;
    int rc = ec2_percent_encode(value, &encoded);
    if (rc != 0) {
        return rc;
    }

    size_t name_length = strlen(name);
    size_t encoded_length = strlen(encoded);
    if (params->length > 0) {
        rc = params_append(params, "&", 1);
    }
    if (rc == 0) {
        rc = params_append(params, name, name_length);
    }
    if (rc == 0) {
        rc = params_append(params, "=", 1);
    }
    if (rc == 0) {
        rc = params_append(params, encoded, encoded_length);
    }

    free(encoded);
    return rc;
}

int ec2_params_add_int(ec2_params *params, const char *name, long value)
{
    char text[32];

    snprintf(text, sizeof(text), "%ld", value);
    return ec2_params_add(params, name, text);
}

int ec2_params_done(ec2_params *params, const char **body, size_t *length)
{
    if (params == NULL || body == NULL || length == NULL) {
        return EINVAL;
    }
    if (params->oom) {
        return ENOMEM;
    }
    if (params->body == NULL) {
        if (params_reserve(params, 0) != 0) {
            return ENOMEM;
        }
        params->body[0] = '\0';
    }
    *body = params->body;
    *length = params->length;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* XML scanning                                                              */
/* ------------------------------------------------------------------------- */

/*
 * Classify the markup at `cursor` (which must point at '<'). Returns 1 when it
 * is `tag` (opening or closing), writing the position just past '>' and whether
 * the element was self-closing.
 */
static int tag_at(const char *cursor, const char *doc_end, const char *tag,
                  int *is_close, int *is_self_closing, const char **after)
{
    size_t tag_length = strlen(tag);
    const char *p = cursor;

    if (p >= doc_end || *p != '<') {
        return 0;
    }
    p++;

    *is_close = 0;
    if (p < doc_end && *p == '/') {
        *is_close = 1;
        p++;
    }
    if ((size_t)(doc_end - p) < tag_length || memcmp(p, tag, tag_length) != 0) {
        return 0;
    }
    p += tag_length;
    if (p >= doc_end) {
        return 0;
    }
    if (!(*p == '>' || *p == '/' || isspace((unsigned char)*p))) {
        return 0;
    }

    const char *close = memchr(p, '>', (size_t)(doc_end - p));
    if (close == NULL) {
        return 0;
    }

    *is_self_closing = 0;
    if (!*is_close) {
        const char *last = close;
        while (last > p && isspace((unsigned char)last[-1])) {
            last--;
        }
        if (last > p && last[-1] == '/') {
            *is_self_closing = 1;
        }
    }
    *after = close + 1;
    return 1;
}

int ec2_xml_next(const char *cursor, const char *doc_end, const char *tag,
                 ec2_xml_span *inner, const char **next_cursor)
{
    if (cursor == NULL || doc_end == NULL || tag == NULL || inner == NULL ||
        next_cursor == NULL || cursor >= doc_end) {
        return 0;
    }

    /* Find the opening element. */
    const char *open_after = NULL;
    int open_self_closing = 0;
    const char *p = cursor;
    while (p < doc_end) {
        const char *markup = memchr(p, '<', (size_t)(doc_end - p));
        if (markup == NULL) {
            return 0;
        }
        int is_close = 0;
        int is_self_closing = 0;
        const char *after = NULL;
        if (tag_at(markup, doc_end, tag, &is_close, &is_self_closing, &after) &&
            !is_close) {
            open_after = after;
            open_self_closing = is_self_closing;
            break;
        }
        p = markup + 1;
    }
    if (open_after == NULL) {
        return 0;
    }

    if (open_self_closing) {
        inner->begin = open_after;
        inner->end = open_after;
        *next_cursor = open_after;
        return 1;
    }

    /* Walk to the matching close, counting same-named nesting. */
    int depth = 1;
    const char *scan = open_after;
    while (scan < doc_end) {
        const char *markup = memchr(scan, '<', (size_t)(doc_end - scan));
        if (markup == NULL) {
            return 0;
        }
        int is_close = 0;
        int is_self_closing = 0;
        const char *after = NULL;
        if (!tag_at(markup, doc_end, tag, &is_close, &is_self_closing, &after)) {
            scan = markup + 1;
            continue;
        }
        if (is_close) {
            depth--;
            if (depth == 0) {
                inner->begin = open_after;
                inner->end = markup;
                *next_cursor = after;
                return 1;
            }
        } else if (!is_self_closing) {
            depth++;
        }
        scan = after;
    }
    return 0;
}

int ec2_xml_text(const ec2_xml_span *span, const char *tag, char *out,
                 size_t out_size)
{
    if (span == NULL || tag == NULL || out == NULL || out_size == 0) {
        return 0;
    }

    ec2_xml_span inner;
    const char *next = NULL;
    if (!ec2_xml_next(span->begin, span->end, tag, &inner, &next)) {
        return 0;
    }
    ec2_xml_decode(inner.begin, (size_t)(inner.end - inner.begin), out,
                   out_size);
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Entity decoding                                                           */
/* ------------------------------------------------------------------------- */

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

void ec2_xml_decode(const char *text, size_t length, char *out,
                    size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }
    if (text == NULL) {
        text = "";
        length = 0;
    }

    size_t source = 0;
    size_t target = 0;
    while (source < length && target + 1 < out_size) {
        char c = text[source];
        if (c != '&') {
            out[target++] = c;
            source++;
            continue;
        }

        const char *entity = text + source;
        size_t remaining = length - source;
        const char *replacement = NULL;
        size_t consumed = 0;

        if (remaining >= 5 && memcmp(entity, "&amp;", 5) == 0) {
            replacement = "&";
            consumed = 5;
        } else if (remaining >= 4 && memcmp(entity, "&lt;", 4) == 0) {
            replacement = "<";
            consumed = 4;
        } else if (remaining >= 4 && memcmp(entity, "&gt;", 4) == 0) {
            replacement = ">";
            consumed = 4;
        } else if (remaining >= 6 && memcmp(entity, "&quot;", 6) == 0) {
            replacement = "\"";
            consumed = 6;
        } else if (remaining >= 6 && memcmp(entity, "&apos;", 6) == 0) {
            replacement = "'";
            consumed = 6;
        }

        if (replacement != NULL) {
            out[target++] = replacement[0];
            source += consumed;
            continue;
        }

        if (remaining >= 4 && entity[1] == '#') {
            size_t index = 2;
            int base = 10;
            if (entity[index] == 'x' || entity[index] == 'X') {
                base = 16;
                index++;
            }
            unsigned long value = 0;
            size_t digits = 0;
            while (index + 1 < remaining && entity[index] != ';') {
                int digit = base == 16 ? hex_value(entity[index])
                                       : (entity[index] >= '0' &&
                                                  entity[index] <= '9'
                                              ? entity[index] - '0'
                                              : -1);
                if (digit < 0) {
                    break;
                }
                value = value * (unsigned long)base + (unsigned long)digit;
                if (value > 0x10ffff) {
                    value = 0x10ffff;
                }
                index++;
                digits++;
            }
            if (digits > 0 && index < remaining && entity[index] == ';') {
                if (value < 0x80) {
                    out[target++] = (char)value;
                    source += index + 1;
                    continue;
                }
                source += index + 1;
                continue;
            }
        }

        out[target++] = c;
        source++;
    }
    out[target] = '\0';
}

/* ------------------------------------------------------------------------- */
/* Base64                                                                    */
/* ------------------------------------------------------------------------- */

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

int ec2_base64_decode(const char *input, size_t input_length, char **out)
{
    if (out == NULL || (input == NULL && input_length != 0)) {
        return EINVAL;
    }

    char *decoded = malloc(input_length + 1);
    if (decoded == NULL) {
        return ENOMEM;
    }

    uint32_t accumulator = 0;
    int bits = 0;
    size_t target = 0;
    size_t characters = 0;
    size_t padding = 0;
    int saw_padding = 0;

    for (size_t i = 0; i < input_length; i++) {
        unsigned char c = (unsigned char)input[i];
        if (isspace(c)) {
            continue;
        }
        if (c == '=') {
            saw_padding = 1;
            padding++;
            continue;
        }
        if (saw_padding) {
            free(decoded);
            return EINVAL;
        }
        int value = base64_value(c);
        if (value < 0) {
            free(decoded);
            return EINVAL;
        }
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        characters++;
        if (bits >= 8) {
            bits -= 8;
            decoded[target++] = (char)((accumulator >> bits) & 0xff);
        }
    }

    if (padding > 2) {
        free(decoded);
        return EINVAL;
    }
    if (padding > 0 && (characters + padding) % 4 != 0) {
        free(decoded);
        return EINVAL;
    }
    if (characters % 4 == 1) {
        free(decoded);
        return EINVAL;
    }

    decoded[target] = '\0';
    *out = decoded;
    return 0;
}
