/*
 * iam.c — AWS IAM + STS Query-protocol client over core/aws.
 *
 * Every operation is a form-encoded `POST /` Query request and an XML
 * response. The module owns request shapes, escaping, XML parsing, pagination
 * and AWS error translation; it never owns credentials, transport or retry
 * policy. No socket symbols: all traffic goes through aws_request().
 */

#include "iam_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- transport seam ----------------------------------------------------- */

/*
 * Test-only transport override. Unit tests set this through
 * iam_test_set_transport(); production leaves it NULL and uses aws_request().
 */
static iam_transport_fn test_transport;
static void *test_transport_ud;

void iam_test_set_transport(iam_transport_fn fn, void *ud)
{
    test_transport = fn;
    test_transport_ud = ud;
}

static int iam_transport(aws_ctx *ctx, const aws_req *req, aws_resp *resp)
{
    if (test_transport != NULL) {
        return test_transport(ctx, req, resp, test_transport_ud);
    }
    return aws_request(ctx, req, resp);
}

/* --- growable form body ------------------------------------------------- */

typedef struct body_builder {
    char *data;
    size_t length;
    size_t capacity;
    int failed;
} body_builder;

static int builder_reserve(body_builder *builder, size_t extra)
{
    if (builder->failed) {
        return ENOMEM;
    }
    if (builder->length + extra + 1 <= builder->capacity) {
        return 0;
    }
    size_t capacity = builder->capacity == 0 ? 128 : builder->capacity;
    while (capacity < builder->length + extra + 1) {
        capacity *= 2;
    }
    char *grown = realloc(builder->data, capacity);
    if (grown == NULL) {
        builder->failed = 1;
        return ENOMEM;
    }
    builder->data = grown;
    builder->capacity = capacity;
    return 0;
}

static int builder_append(body_builder *builder, const char *text, size_t length)
{
    int rc = builder_reserve(builder, length);
    if (rc != 0) {
        return rc;
    }
    memcpy(builder->data + builder->length, text, length);
    builder->length += length;
    builder->data[builder->length] = '\0';
    return 0;
}

static int is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
           c == '~';
}

/* Append `&name=` plus the RFC 3986 percent-encoding of `value`. */
static int builder_add(body_builder *builder, const char *name,
                       const char *value)
{
    static const char hex[] = "0123456789ABCDEF";

    int rc = 0;
    if (builder->length > 0) {
        rc = builder_append(builder, "&", 1);
        if (rc != 0) {
            return rc;
        }
    }
    rc = builder_append(builder, name, strlen(name));
    if (rc != 0) {
        return rc;
    }
    rc = builder_append(builder, "=", 1);
    if (rc != 0) {
        return rc;
    }

    size_t length = strlen(value);
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)value[i];
        if (is_unreserved(byte)) {
            rc = builder_append(builder, (const char *)&value[i], 1);
        } else {
            char encoded[3] = {'%', hex[byte >> 4], hex[byte & 0x0f]};
            rc = builder_append(builder, encoded, sizeof encoded);
        }
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int iam_build_body(const char *action, const char *version,
                   const char *user_name, const char *access_key_id,
                   const char *marker, char **out_body, size_t *out_len)
{
    if (action == NULL || version == NULL || out_body == NULL ||
        out_len == NULL) {
        return EINVAL;
    }

    body_builder builder = {0};
    int rc = builder_add(&builder, "Action", action);
    if (rc == 0) {
        rc = builder_add(&builder, "Version", version);
    }
    if (rc == 0 && user_name != NULL) {
        rc = builder_add(&builder, "UserName", user_name);
    }
    if (rc == 0 && access_key_id != NULL) {
        rc = builder_add(&builder, "AccessKeyId", access_key_id);
    }
    if (rc == 0 && marker != NULL) {
        rc = builder_add(&builder, "Marker", marker);
    }

    if (rc != 0) {
        free(builder.data);
        return rc;
    }

    *out_body = builder.data;
    *out_len = builder.length;
    return 0;
}

/* --- XML helper --------------------------------------------------------- */

typedef struct xml_span {
    const char *begin;
    const char *end;
} xml_span;

/*
 * Classify the markup at `cursor` (which must point at '<'). On a match,
 * writes whether it was a closing tag, whether it was self-closing, and the
 * position just past its '>'. Returns 1 on match, 0 otherwise.
 */
static int match_tag(const char *cursor, const char *doc_end, const char *tag,
                     int *is_close, int *is_self, const char **after_gt)
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
    if ((size_t)(doc_end - p) < tag_length) {
        return 0;
    }
    if (memcmp(p, tag, tag_length) != 0) {
        return 0;
    }
    p += tag_length;
    if (p >= doc_end) {
        return 0;
    }
    if (*p != '>' && *p != '/' && !isspace((unsigned char)*p)) {
        return 0;
    }
    const char *open_end = p;
    while (p < doc_end && *p != '>') {
        p++;
    }
    if (p >= doc_end) {
        return 0;
    }
    *is_self = (!*is_close && open_end < p && p[-1] == '/');
    *after_gt = p + 1;
    return 1;
}

/*
 * Find the next `<tag>...</tag>` block at or after `cursor`, honouring nesting
 * of same-named tags. On success writes the inner content span and the position
 * just past the closing tag. Returns 1 when found, 0 when not.
 */
static int xml_next(const char *cursor, const char *doc_end, const char *tag,
                    xml_span *inner, const char **after)
{
    const char *open_gt = NULL;
    const char *p = cursor;

    for (; p < doc_end; p++) {
        if (*p != '<') {
            continue;
        }
        int is_close = 0;
        int is_self = 0;
        const char *after_gt = NULL;
        if (!match_tag(p, doc_end, tag, &is_close, &is_self, &after_gt)) {
            continue;
        }
        if (is_close) {
            continue;
        }
        if (is_self) {
            inner->begin = after_gt;
            inner->end = after_gt;
            *after = after_gt;
            return 1;
        }
        open_gt = after_gt;
        break;
    }
    if (open_gt == NULL) {
        return 0;
    }

    int depth = 1;
    const char *scan = open_gt;
    while (scan < doc_end) {
        if (*scan != '<') {
            scan++;
            continue;
        }
        int is_close = 0;
        int is_self = 0;
        const char *after_gt = NULL;
        if (!match_tag(scan, doc_end, tag, &is_close, &is_self, &after_gt)) {
            scan++;
            continue;
        }
        if (is_close) {
            depth--;
            if (depth == 0) {
                inner->begin = open_gt;
                inner->end = scan;
                *after = after_gt;
                return 1;
            }
        } else if (!is_self) {
            depth++;
        }
        scan = after_gt;
    }
    return 0;
}

/* Entity-decode `length` bytes at `text` into `out` (NUL-terminated). */
static void xml_decode(const char *text, size_t length, char *out,
                       size_t out_size)
{
    size_t position = 0;
    for (size_t i = 0; i < length && position + 1 < out_size; i++) {
        if (text[i] != '&') {
            out[position++] = text[i];
            continue;
        }
        struct {
            const char *entity;
            char replacement;
        } const entities[] = {
            {"&amp;", '&'},  {"&lt;", '<'},  {"&gt;", '>'},
            {"&quot;", '"'}, {"&apos;", '\''},
        };
        int matched = 0;
        for (size_t e = 0; e < sizeof entities / sizeof entities[0]; e++) {
            size_t entity_length = strlen(entities[e].entity);
            if (i + entity_length <= length &&
                memcmp(text + i, entities[e].entity, entity_length) == 0) {
                out[position++] = entities[e].replacement;
                i += entity_length - 1;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            out[position++] = text[i];
        }
    }
    out[position] = '\0';
}

/* Copy the text of the first `<tag>` inside `container` into `out`. Returns 1
 * when found, 0 when absent. Truncates safely. */
static int xml_text(const xml_span *container, const char *tag, char *out,
                    size_t out_size)
{
    xml_span inner;
    const char *after = NULL;
    if (!xml_next(container->begin, container->end, tag, &inner, &after)) {
        return 0;
    }
    (void)after;
    xml_decode(inner.begin, (size_t)(inner.end - inner.begin), out, out_size);
    return 1;
}

/* Heap-allocate the decoded text of `tag`, or NULL when absent/OOM. */
static char *xml_dup(const xml_span *container, const char *tag)
{
    xml_span inner;
    const char *after = NULL;
    if (!xml_next(container->begin, container->end, tag, &inner, &after)) {
        return NULL;
    }
    (void)after;
    size_t length = (size_t)(inner.end - inner.begin);
    char *value = malloc(length + 1);
    if (value == NULL) {
        return NULL;
    }
    xml_decode(inner.begin, length, value, length + 1);
    return value;
}

/* --- request/error plumbing --------------------------------------------- */

/* Copy the AWS error code/message from `resp` to stderr and translate it. */
static int report_api_error(const char *action, aws_resp *resp)
{
    char code[IAM_ERROR_CODE_MAX] = {0};
    char message[IAM_ERROR_MESSAGE_MAX] = {0};

    if (resp != NULL && resp->body != NULL) {
        xml_span document = {resp->body, resp->body + resp->body_len};
        (void)xml_text(&document, "Code", code, sizeof code);
        (void)xml_text(&document, "Message", message, sizeof message);
    }
    if (code[0] == '\0') {
        snprintf(code, sizeof code, "HTTP%ld",
                 resp != NULL ? resp->status : 0L);
    }

    fprintf(stderr, "stackctl: iam %s failed: %s%s%s\n",
            action != NULL ? action : "request", code,
            message[0] != '\0' ? ": " : "", message);

    if (strcmp(code, "NoSuchEntity") == 0) {
        return ENOENT;
    }
    if (strcmp(code, "AccessDenied") == 0 ||
        strcmp(code, "InvalidClientTokenId") == 0 ||
        strcmp(code, "SignatureDoesNotMatch") == 0 ||
        strcmp(code, "UnrecognizedClientException") == 0 ||
        strcmp(code, "AuthFailure") == 0) {
        return EACCES;
    }
    return IAM_ERR_AWS_API;
}

/*
 * Issue one Query operation. On an HTTP error response this reports the AWS
 * error and returns its translated code; on success `resp` is owned by the
 * caller (aws_resp_free).
 */
static int iam_call(aws_ctx *ctx, const char *service, const char *action,
                    const char *version, const char *user_name,
                    const char *access_key_id, const char *marker,
                    aws_resp *resp)
{
    if (ctx == NULL || service == NULL || action == NULL || version == NULL ||
        resp == NULL) {
        return EINVAL;
    }

    char *body = NULL;
    size_t body_length = 0;
    int rc = iam_build_body(action, version, user_name, access_key_id, marker,
                            &body, &body_length);
    if (rc != 0) {
        return rc;
    }

    aws_req request = {
        .service = service,
        .region = IAM_SIGNING_REGION,
        .method = "POST",
        .path = "/",
        .query = NULL,
        .body = body,
        .body_len = body_length,
        .content_type = "application/x-www-form-urlencoded",
        /* IAM's Query API is global; STS keeps its regional host. */
        .host = strcmp(service, "iam") == 0 ? IAM_GLOBAL_ENDPOINT : NULL,
        .unsigned_payload = 0,
    };

    memset(resp, 0, sizeof(*resp));
    rc = iam_transport(ctx, &request, resp);
    free(body);
    if (rc != 0) {
        return rc;
    }
    if (resp->status < 200 || resp->status >= 300) {
        rc = report_api_error(action, resp);
    }
    return rc;
}

/* --- key lifecycle ------------------------------------------------------ */

static void key_free_fields(iam_key *key)
{
    free(key->user_name);
    free(key->access_key_id);
    free(key->secret_access_key);
    free(key->status);
    free(key->create_date);
    memset(key, 0, sizeof(*key));
}

void iam_key_free(iam_key *key)
{
    if (key == NULL) {
        return;
    }
    key_free_fields(key);
}

void iam_keys_free(iam_key *keys, size_t count)
{
    if (keys == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        key_free_fields(&keys[i]);
    }
    free(keys);
}

/* Parse one `<member>` element of AccessKeyMetadata / one `<AccessKey>`. */
static int parse_key(const xml_span *container, iam_key *key)
{
    memset(key, 0, sizeof(*key));
    key->user_name = xml_dup(container, "UserName");
    key->access_key_id = xml_dup(container, "AccessKeyId");
    key->secret_access_key = xml_dup(container, "SecretAccessKey");
    key->status = xml_dup(container, "Status");
    key->create_date = xml_dup(container, "CreateDate");

    if (key->access_key_id == NULL) {
        key_free_fields(key);
        return EBADMSG;
    }
    return 0;
}

static int list_append(iam_key **keys, size_t *count, iam_key *key)
{
    iam_key *grown = realloc(*keys, (*count + 1) * sizeof(*grown));
    if (grown == NULL) {
        return ENOMEM;
    }
    *keys = grown;
    (*keys)[*count] = *key;
    (*count)++;
    memset(key, 0, sizeof(*key));
    return 0;
}

/* Parse all `<member>` keys inside `<AccessKeyMetadata>` in `document`. */
static int parse_key_page(const xml_span *document, iam_key **keys,
                          size_t *count)
{
    xml_span metadata;
    const char *after = NULL;
    if (!xml_next(document->begin, document->end, "AccessKeyMetadata",
                  &metadata, &after)) {
        return 0;
    }

    const char *cursor = metadata.begin;
    while (cursor < metadata.end) {
        xml_span member;
        if (!xml_next(cursor, metadata.end, "member", &member, &after)) {
            break;
        }
        iam_key key;
        int rc = parse_key(&member, &key);
        if (rc != 0) {
            return rc;
        }
        rc = list_append(keys, count, &key);
        if (rc != 0) {
            key_free_fields(&key);
            return rc;
        }
        cursor = after;
    }
    return 0;
}

int iam_get_caller_identity(aws_ctx *ctx, char **out_account, char **out_arn,
                            char **out_user_id)
{
    if (ctx == NULL) {
        return EINVAL;
    }

    aws_resp response = {0};
    int rc = iam_call(ctx, "sts", "GetCallerIdentity", IAM_STS_API_VERSION,
                      NULL, NULL, NULL, &response);
    char *account = NULL;
    char *arn = NULL;
    char *user_id = NULL;
    if (rc == 0) {
        xml_span document = {response.body,
                             response.body + response.body_len};
        account = xml_dup(&document, "Account");
        arn = xml_dup(&document, "Arn");
        user_id = xml_dup(&document, "UserId");
        if (account == NULL || arn == NULL || user_id == NULL) {
            rc = EBADMSG;
        }
    }
    aws_resp_free(&response);

    if (rc != 0) {
        free(account);
        free(arn);
        free(user_id);
        return rc;
    }

    if (out_account != NULL) {
        *out_account = account;
    } else {
        free(account);
    }
    if (out_arn != NULL) {
        *out_arn = arn;
    } else {
        free(arn);
    }
    if (out_user_id != NULL) {
        *out_user_id = user_id;
    } else {
        free(user_id);
    }
    return 0;
}

int iam_list_access_keys(aws_ctx *ctx, const char *user_name_or_null,
                         iam_key **out, size_t *out_count)
{
    if (ctx == NULL || out == NULL || out_count == NULL) {
        return EINVAL;
    }

    iam_key *keys = NULL;
    size_t count = 0;
    char *marker = strdup("");
    if (marker == NULL) {
        return ENOMEM;
    }

    int rc = 0;
    for (int page = 0; page < IAM_MAX_PAGES; page++) {
        const char *marker_or_null = marker[0] != '\0' ? marker : NULL;
        aws_resp response = {0};
        rc = iam_call(ctx, "iam", "ListAccessKeys", IAM_API_VERSION,
                      user_name_or_null, NULL, marker_or_null, &response);
        if (rc != 0) {
            aws_resp_free(&response);
            break;
        }

        xml_span document = {response.body, response.body + response.body_len};
        rc = parse_key_page(&document, &keys, &count);

        char truncated[16] = {0};
        char next_marker[1024] = {0};
        if (rc == 0) {
            (void)xml_text(&document, "IsTruncated", truncated,
                           sizeof truncated);
            int more = strcmp(truncated, "true") == 0;
            if (more) {
                (void)xml_text(&document, "Marker", next_marker,
                               sizeof next_marker);
                if (next_marker[0] == '\0') {
                    rc = EBADMSG;
                }
            }
            aws_resp_free(&response);
            if (rc != 0) {
                break;
            }
            if (!more) {
                free(marker);
                *out = keys;
                *out_count = count;
                return 0;
            }
            char *replacement = strdup(next_marker);
            if (replacement == NULL) {
                rc = ENOMEM;
                break;
            }
            free(marker);
            marker = replacement;
        } else {
            aws_resp_free(&response);
            break;
        }
    }

    if (rc == 0) {
        /* Ran past IAM_MAX_PAGES while AWS still reported truncation. */
        rc = EIO;
    }
    free(marker);
    iam_keys_free(keys, count);
    return rc;
}

int iam_create_access_key(aws_ctx *ctx, const char *user_name_or_null,
                          iam_key *out)
{
    if (ctx == NULL || out == NULL) {
        return EINVAL;
    }

    aws_resp response = {0};
    int rc = iam_call(ctx, "iam", "CreateAccessKey", IAM_API_VERSION,
                      user_name_or_null, NULL, NULL, &response);
    iam_key key = {0};
    if (rc == 0) {
        xml_span document = {response.body,
                             response.body + response.body_len};
        xml_span access_key;
        const char *after = NULL;
        if (!xml_next(document.begin, document.end, "AccessKey", &access_key,
                      &after)) {
            rc = EBADMSG;
        } else {
            rc = parse_key(&access_key, &key);
        }
    }
    aws_resp_free(&response);

    if (rc != 0) {
        key_free_fields(&key);
        return rc;
    }
    *out = key;
    return 0;
}

int iam_delete_access_key(aws_ctx *ctx, const char *user_name_or_null,
                          const char *access_key_id)
{
    if (ctx == NULL || access_key_id == NULL) {
        return EINVAL;
    }

    aws_resp response = {0};
    int rc = iam_call(ctx, "iam", "DeleteAccessKey", IAM_API_VERSION,
                      user_name_or_null, access_key_id, NULL, &response);
    aws_resp_free(&response);
    return rc;
}
