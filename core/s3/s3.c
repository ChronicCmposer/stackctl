/*
 * s3.c — S3 request builders and response parsers over core/aws (spec §5.5).
 *
 * Path-style addressing only. PUT/GET/HEAD are signed with `UNSIGNED-PAYLOAD`
 * (spec §5.5); object integrity is provided by the caller's own sha256
 * read-back helpers below. No multipart uploads: one PUT per object.
 */

#include "s3_internal.h"

#include "../crypto/crypto.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define S3_XML_CONTENT_TYPE "application/xml"
#define S3_PARAM_MAX 512

struct s3_client {
    aws_ctx *aws; /* not owned */
    char *region;
    s3_transport_fn transport;
    void *transport_ud;
};

static int aws_request_transport(void *ud, const aws_req *req, aws_resp *resp)
{
    return aws_request((aws_ctx *)ud, req, resp);
}

/* --- small helpers ------------------------------------------------------ */

static int valid_bucket(const char *bucket)
{
    return bucket != NULL && bucket[0] != '\0' && strchr(bucket, '/') == NULL &&
           strchr(bucket, '\\') == NULL;
}

static int valid_key(const char *key)
{
    return key != NULL && key[0] != '\0';
}

/*
 * Percent-encode `in` for a canonical S3 URI/query value. Unreserved bytes
 * (ALPHA / DIGIT / '-' '.' '_' '~') pass through; '/' passes through only when
 * `keep_slash` is set (object keys keep their separators in the path).
 */
static int percent_encode(const char *in, int keep_slash, char **out)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t len = strlen(in);
    char *encoded = malloc(len * 3 + 1);
    if (encoded == NULL) {
        return ENOMEM;
    }
    size_t used = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~' ||
            (keep_slash && c == '/')) {
            encoded[used++] = (char)c;
        } else {
            encoded[used++] = '%';
            encoded[used++] = hex[c >> 4];
            encoded[used++] = hex[c & 0x0f];
        }
    }
    encoded[used] = '\0';
    *out = encoded;
    return 0;
}

static int build_path(const char *bucket, const char *key, char **out)
{
    if (!valid_bucket(bucket)) {
        return EINVAL;
    }
    char *encoded_bucket = NULL;
    int rc = percent_encode(bucket, 0, &encoded_bucket);
    if (rc != 0) {
        return rc;
    }
    if (key == NULL || key[0] == '\0') {
        size_t need = strlen(encoded_bucket) + 2;
        char *path = malloc(need);
        if (path == NULL) {
            free(encoded_bucket);
            return ENOMEM;
        }
        snprintf(path, need, "/%s", encoded_bucket);
        *out = path;
        free(encoded_bucket);
        return 0;
    }

    char *encoded_key = NULL;
    rc = percent_encode(key, 1, &encoded_key);
    if (rc != 0) {
        free(encoded_bucket);
        return rc;
    }
    size_t need = strlen(encoded_bucket) + strlen(encoded_key) + 3;
    char *path = malloc(need);
    if (path == NULL) {
        free(encoded_bucket);
        free(encoded_key);
        return ENOMEM;
    }
    snprintf(path, need, "/%s/%s", encoded_bucket, encoded_key);
    *out = path;
    free(encoded_bucket);
    free(encoded_key);
    return 0;
}

/* Decode the five XML predefined entities and numeric character references. */
static char *xml_decode(const char *text, size_t len)
{
    char *out = malloc(len + 1);
    if (out == NULL) {
        return NULL;
    }
    size_t used = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] != '&') {
            out[used++] = text[i];
            continue;
        }
        const char *semi = memchr(text + i, ';', len - i);
        if (semi == NULL) {
            out[used++] = text[i];
            continue;
        }
        size_t entity_len = (size_t)(semi - (text + i + 1));
        const char *entity = text + i + 1;
        char decoded = '\0';
        int known = 1;
        if (entity_len == 3 && memcmp(entity, "amp", 3) == 0) {
            decoded = '&';
        } else if (entity_len == 2 && memcmp(entity, "lt", 2) == 0) {
            decoded = '<';
        } else if (entity_len == 2 && memcmp(entity, "gt", 2) == 0) {
            decoded = '>';
        } else if (entity_len == 4 && memcmp(entity, "quot", 4) == 0) {
            decoded = '"';
        } else if (entity_len == 4 && memcmp(entity, "apos", 4) == 0) {
            decoded = '\'';
        } else if (entity_len >= 2 && entity[0] == '#') {
            char *end = NULL;
            long value;
            if (entity[1] == 'x' || entity[1] == 'X') {
                value = strtol(entity + 2, &end, 16);
            } else {
                value = strtol(entity + 1, &end, 10);
            }
            if (end == NULL || end != semi || value < 0 || value > 0x7f) {
                known = 0;
            } else {
                decoded = (char)value;
            }
        } else {
            known = 0;
        }
        if (known) {
            out[used++] = decoded;
            i = (size_t)(semi - text);
        } else {
            out[used++] = text[i];
        }
    }
    out[used] = '\0';
    return out;
}

/*
 * Extract and decode the text of the first <tag>...</tag> inside
 * [begin, end). Returns NULL when the tag is absent or unterminated; an empty
 * or self-closing element yields an empty heap string.
 */
static char *xml_text_range(const char *begin, const char *end, const char *tag)
{
    if (begin == NULL || end == NULL || tag == NULL) {
        return NULL;
    }
    char open[S3_PARAM_MAX];
    char close[S3_PARAM_MAX];
    int n = snprintf(open, sizeof(open), "<%s", tag);
    if (n < 0 || (size_t)n >= sizeof(open)) {
        return NULL;
    }
    n = snprintf(close, sizeof(close), "</%s>", tag);
    if (n < 0 || (size_t)n >= sizeof(close)) {
        return NULL;
    }
    size_t open_len = strlen(open);
    size_t close_len = strlen(close);

    const char *p = begin;
    while ((p = strstr(p, open)) != NULL && p < end) {
        const char *after = p + open_len;
        if (after >= end) {
            return NULL;
        }
        if (*after == '/') {
            return strdup("");
        }
        if (*after != '>' && *after != ' ' && *after != '\n' && *after != '\t') {
            p = after;
            continue;
        }
        const char *gt = strchr(after, '>');
        if (gt == NULL || gt >= end) {
            return NULL;
        }
        const char *start = gt + 1;
        const char *stop = strstr(start, close);
        if (stop == NULL || stop + close_len > end) {
            return NULL;
        }
        return xml_decode(start, (size_t)(stop - start));
    }
    return NULL;
}

static char *xml_text(const char *xml, const char *tag)
{
    if (xml == NULL) {
        return NULL;
    }
    return xml_text_range(xml, xml + strlen(xml), tag);
}

static int xml_bool(const char *xml, const char *tag, int *out)
{
    char *value = xml_text(xml, tag);
    if (value == NULL) {
        *out = 0;
        return 0;
    }
    *out = strcmp(value, "true") == 0 || strcmp(value, "TRUE") == 0;
    free(value);
    return 0;
}

/* Append an XML-escaped `value` to `cursor` within `cap`. Returns 0/-1. */
static int append_escaped(char *buffer, size_t cap, size_t *used,
                          const char *value)
{
    for (const char *p = value; *p != '\0'; p++) {
        const char *entity = NULL;
        switch (*p) {
        case '&':
            entity = "&amp;";
            break;
        case '<':
            entity = "&lt;";
            break;
        case '>':
            entity = "&gt;";
            break;
        case '"':
            entity = "&quot;";
            break;
        case '\'':
            entity = "&apos;";
            break;
        default:
            break;
        }
        if (entity != NULL) {
            size_t len = strlen(entity);
            if (*used + len >= cap) {
                return -1;
            }
            memcpy(buffer + *used, entity, len);
            *used += len;
        } else {
            if (*used + 1 >= cap) {
                return -1;
            }
            buffer[(*used)++] = *p;
        }
    }
    buffer[*used] = '\0';
    return 0;
}

static void copy_etag(const aws_resp *resp, char out[S3_ETAG_MAX])
{
    const char *etag = aws_resp_header(resp, "ETag");
    if (etag == NULL) {
        out[0] = '\0';
        return;
    }
    size_t len = strlen(etag);
    if (len >= 2 && etag[0] == '"' && etag[len - 1] == '"') {
        etag++;
        len -= 2;
    }
    if (len >= S3_ETAG_MAX) {
        len = S3_ETAG_MAX - 1;
    }
    memcpy(out, etag, len);
    out[len] = '\0';
}

static int parse_size(const char *text, unsigned long long *out)
{
    if (text == NULL || text[0] == '\0') {
        return EIO;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return EIO;
    }
    *out = value;
    return 0;
}

int s3_status_to_errno(long status, const char *code)
{
    if (status >= 200 && status < 300) {
        return 0;
    }
    if (code != NULL && code[0] != '\0') {
        if (strcmp(code, "NoSuchKey") == 0 ||
            strcmp(code, "NoSuchBucket") == 0 ||
            strcmp(code, "NoSuchVersion") == 0 ||
            strcmp(code, "NoSuchLifecycleConfiguration") == 0 ||
            strcmp(code, "NoSuchPublicAccessBlockConfiguration") == 0 ||
            strcmp(code, "ServerSideEncryptionConfigurationNotFoundError") == 0 ||
            strcmp(code, "NotFound") == 0) {
            return ENOENT;
        }
        if (strcmp(code, "AccessDenied") == 0 ||
            strcmp(code, "AllAccessDisabled") == 0 ||
            strcmp(code, "InvalidAccessKeyId") == 0 ||
            strcmp(code, "SignatureDoesNotMatch") == 0) {
            return EACCES;
        }
        if (strcmp(code, "BucketAlreadyExists") == 0 ||
            strcmp(code, "BucketAlreadyOwnedByYou") == 0) {
            return EEXIST;
        }
        if (strcmp(code, "InvalidBucketName") == 0 ||
            strcmp(code, "InvalidArgument") == 0 ||
            strcmp(code, "MalformedXML") == 0) {
            return EINVAL;
        }
    }
    switch (status) {
    case 400:
        return EINVAL;
    case 403:
        return EACCES;
    case 404:
        return ENOENT;
    case 409:
        return EEXIST;
    case 412:
        return ESTALE;
    case 429:
        return EAGAIN;
    default:
        return EIO;
    }
}

/* --- client ------------------------------------------------------------- */

int s3_client_init_with_transport(s3_client **out, const char *region,
                                  s3_transport_fn transport, void *ud)
{
    if (out == NULL || region == NULL || region[0] == '\0' ||
        transport == NULL) {
        return EINVAL;
    }
    *out = NULL;
    s3_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return ENOMEM;
    }
    client->region = strdup(region);
    if (client->region == NULL) {
        free(client);
        return ENOMEM;
    }
    client->transport = transport;
    client->transport_ud = ud;
    *out = client;
    return 0;
}

int s3_client_init(s3_client **out, aws_ctx *aws, const char *region)
{
    if (aws == NULL) {
        return EINVAL;
    }
    int rc = s3_client_init_with_transport(out, region, aws_request_transport,
                                           aws);
    if (rc == 0) {
        (*out)->aws = aws;
    }
    return rc;
}

void s3_client_free(s3_client *client)
{
    if (client == NULL) {
        return;
    }
    free(client->region);
    free(client);
}

/* --- request core ------------------------------------------------------- */

/*
 * Build and send one request. On a non-2xx response the AWS error code (XML or
 * JSON) is mapped to an errno-style code and the response is released. On
 * success the caller owns `resp` and must aws_resp_free() it.
 */
static int s3_call(s3_client *client, const char *method, const char *bucket,
                   const char *key, const char *query, const void *body,
                   size_t body_len, const char *content_type, aws_resp *resp)
{
    if (client == NULL || resp == NULL || method == NULL) {
        return EINVAL;
    }
    char *path = NULL;
    int rc = build_path(bucket, key, &path);
    if (rc != 0) {
        return rc;
    }
    aws_req req = {
        .service = "s3",
        .region = client->region,
        .method = method,
        .path = path,
        .query = query,
        .body = body,
        .body_len = body_len,
        .content_type = content_type,
        .unsigned_payload = strcmp(method, "PUT") == 0 ||
                            strcmp(method, "GET") == 0 ||
                            strcmp(method, "HEAD") == 0,
    };
    memset(resp, 0, sizeof(*resp));
    rc = client->transport(client->transport_ud, &req, resp);
    free(path);
    if (rc != 0) {
        aws_resp_free(resp);
        return rc;
    }
    if (resp->status >= 200 && resp->status < 300) {
        return 0;
    }
    char code[AWS_ERROR_CODE_LEN];
    code[0] = '\0';
    int have_code = aws_error_code(resp, code);
    rc = s3_status_to_errno(resp->status,
                            have_code == 1 ? code : NULL);
    aws_resp_free(resp);
    return rc;
}

/* --- objects ------------------------------------------------------------ */

int s3_put_object(s3_client *client, const char *bucket, const char *key,
                  const void *data, size_t len, const char *content_type,
                  char etag_out[S3_ETAG_MAX])
{
    if (!valid_bucket(bucket) || !valid_key(key) ||
        (data == NULL && len != 0)) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "PUT", bucket, key, NULL, data, len,
                     content_type, &resp);
    if (rc != 0) {
        return rc;
    }
    if (etag_out != NULL) {
        copy_etag(&resp, etag_out);
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_get_object(s3_client *client, const char *bucket, const char *key,
                  char **data_out, size_t *len_out)
{
    if (!valid_bucket(bucket) || !valid_key(key) || data_out == NULL ||
        len_out == NULL) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "GET", bucket, key, NULL, NULL, 0, NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    char *copy = malloc(resp.body_len + 1);
    if (copy == NULL) {
        aws_resp_free(&resp);
        return ENOMEM;
    }
    if (resp.body_len > 0 && resp.body != NULL) {
        memcpy(copy, resp.body, resp.body_len);
    }
    copy[resp.body_len] = '\0';
    *data_out = copy;
    *len_out = resp.body_len;
    aws_resp_free(&resp);
    return 0;
}

int s3_head_object(s3_client *client, const char *bucket, const char *key,
                   unsigned long long *size_out, char etag_out[S3_ETAG_MAX])
{
    if (!valid_bucket(bucket) || !valid_key(key) || size_out == NULL) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "HEAD", bucket, key, NULL, NULL, 0, NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    rc = parse_size(aws_resp_header(&resp, "Content-Length"), size_out);
    if (rc == 0 && etag_out != NULL) {
        copy_etag(&resp, etag_out);
    }
    aws_resp_free(&resp);
    return rc;
}

int s3_delete_object(s3_client *client, const char *bucket, const char *key)
{
    if (!valid_bucket(bucket) || !valid_key(key)) {
        return EINVAL;
    }
    aws_resp resp;
    int rc =
        s3_call(client, "DELETE", bucket, key, NULL, NULL, 0, NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

static int append_object(s3_object_list *out, s3_object_info *item)
{
    s3_object_info *grown =
        realloc(out->items, (out->count + 1) * sizeof(*grown));
    if (grown == NULL) {
        return ENOMEM;
    }
    out->items = grown;
    out->items[out->count++] = *item;
    return 0;
}

static int parse_object_block(const char *begin, const char *end,
                              s3_object_info *item)
{
    memset(item, 0, sizeof(*item));
    item->key = xml_text_range(begin, end, "Key");
    if (item->key == NULL) {
        return EIO;
    }
    char *etag = xml_text_range(begin, end, "ETag");
    if (etag != NULL) {
        size_t len = strlen(etag);
        if (len >= 2 && etag[0] == '"' && etag[len - 1] == '"') {
            memmove(etag, etag + 1, len - 2);
            etag[len - 2] = '\0';
        }
        snprintf(item->etag, sizeof(item->etag), "%s", etag);
        free(etag);
    }
    char *size = xml_text_range(begin, end, "Size");
    if (size != NULL) {
        unsigned long long value = 0;
        if (parse_size(size, &value) == 0) {
            item->size = value;
        }
        free(size);
    }
    char *modified = xml_text_range(begin, end, "LastModified");
    if (modified != NULL) {
        snprintf(item->last_modified, sizeof(item->last_modified), "%s",
                 modified);
        free(modified);
    }
    return 0;
}

int s3_list_objects_v2(s3_client *client, const char *bucket, const char *prefix,
                       s3_object_list *out)
{
    if (!valid_bucket(bucket) || out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));

    char *query = NULL;
    if (prefix != NULL && prefix[0] != '\0') {
        char *encoded = NULL;
        int rc = percent_encode(prefix, 0, &encoded);
        if (rc != 0) {
            return rc;
        }
        size_t need = strlen(encoded) + sizeof("list-type=2&prefix=");
        query = malloc(need);
        if (query == NULL) {
            free(encoded);
            return ENOMEM;
        }
        snprintf(query, need, "list-type=2&prefix=%s", encoded);
        free(encoded);
    } else {
        query = strdup("list-type=2");
        if (query == NULL) {
            return ENOMEM;
        }
    }

    aws_resp resp;
    int rc = s3_call(client, "GET", bucket, NULL, query, NULL, 0, NULL, &resp);
    free(query);
    if (rc != 0) {
        return rc;
    }
    if (resp.body == NULL || resp.body_len == 0) {
        aws_resp_free(&resp);
        return EIO;
    }

    const char *begin = resp.body;
    const char *end = resp.body + resp.body_len;
    const char *cursor = begin;
    while (cursor < end) {
        const char *open = strstr(cursor, "<Contents>");
        if (open == NULL || open >= end) {
            break;
        }
        const char *close = strstr(open, "</Contents>");
        if (close == NULL || close >= end) {
            rc = EIO;
            break;
        }
        s3_object_info item;
        rc = parse_object_block(open + strlen("<Contents>"), close, &item);
        if (rc != 0) {
            free(item.key);
            break;
        }
        rc = append_object(out, &item);
        if (rc != 0) {
            free(item.key);
            break;
        }
        cursor = close + strlen("</Contents>");
    }

    if (rc == 0) {
        char *truncated = xml_text_range(begin, end, "IsTruncated");
        out->truncated = truncated != NULL && strcmp(truncated, "true") == 0;
        free(truncated);
        out->next_token = xml_text_range(begin, end, "NextContinuationToken");
    }

    aws_resp_free(&resp);
    if (rc != 0) {
        s3_object_list_free(out);
    }
    return rc;
}

void s3_object_list_free(s3_object_list *list)
{
    if (list == NULL) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i].key);
    }
    free(list->items);
    free(list->next_token);
    memset(list, 0, sizeof(*list));
}

/* --- sha256 read-back helpers ------------------------------------------ */

int s3_sha256_hex(const void *data, size_t len, char out[S3_SHA256_HEX_LEN])
{
    if (out == NULL || (data == NULL && len != 0)) {
        return EINVAL;
    }
    static const char digits[] = "0123456789abcdef";
    static const uint8_t empty = 0;
    uint8_t digest[CRYPTO_SHA256_DIGEST_LEN];
    crypto_sha256(data != NULL ? data : &empty, len, digest);
    for (size_t i = 0; i < CRYPTO_SHA256_DIGEST_LEN; i++) {
        out[i * 2] = digits[digest[i] >> 4];
        out[i * 2 + 1] = digits[digest[i] & 0x0f];
    }
    out[CRYPTO_SHA256_DIGEST_LEN * 2] = '\0';
    return 0;
}

int s3_sha256_verify(const void *data, size_t len, const char *expected_hex)
{
    if ((data == NULL && len != 0) || expected_hex == NULL) {
        return EINVAL;
    }
    if (strlen(expected_hex) != CRYPTO_SHA256_DIGEST_LEN * 2) {
        return EINVAL;
    }
    for (size_t i = 0; i < CRYPTO_SHA256_DIGEST_LEN * 2; i++) {
        if (!isxdigit((unsigned char)expected_hex[i])) {
            return EINVAL;
        }
    }
    char actual[S3_SHA256_HEX_LEN];
    int rc = s3_sha256_hex(data, len, actual);
    if (rc != 0) {
        return rc;
    }
    return strcasecmp(actual, expected_hex) == 0 ? 0 : EBADMSG;
}

int s3_get_object_sha256(s3_client *client, const char *bucket, const char *key,
                         const char *expected_hex, char **data_out,
                         size_t *len_out)
{
    if (expected_hex == NULL) {
        return EINVAL;
    }
    char *data = NULL;
    size_t len = 0;
    int rc = s3_get_object(client, bucket, key, &data, &len);
    if (rc != 0) {
        return rc;
    }
    rc = s3_sha256_verify(data, len, expected_hex);
    if (rc != 0) {
        free(data);
        return rc;
    }
    *data_out = data;
    *len_out = len;
    return 0;
}

/* --- buckets ------------------------------------------------------------ */

int s3_create_bucket(s3_client *client, const char *bucket)
{
    if (client == NULL || !valid_bucket(bucket)) {
        return EINVAL;
    }
    char body[512];
    const char *payload = NULL;
    size_t payload_len = 0;
    if (strcmp(client->region, "us-east-1") != 0) {
        size_t used = 0;
        int n = snprintf(body, sizeof(body),
                         "<CreateBucketConfiguration "
                         "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                         "<LocationConstraint>");
        if (n < 0 || (size_t)n >= sizeof(body)) {
            return EOVERFLOW;
        }
        used = (size_t)n;
        if (append_escaped(body, sizeof(body), &used, client->region) != 0) {
            return EOVERFLOW;
        }
        n = snprintf(body + used, sizeof(body) - used,
                     "</LocationConstraint></CreateBucketConfiguration>");
        if (n < 0 || (size_t)n >= sizeof(body) - used) {
            return EOVERFLOW;
        }
        payload = body;
        payload_len = used + (size_t)n;
    }
    aws_resp resp;
    int rc = s3_call(client, "PUT", bucket, NULL, NULL, payload, payload_len,
                     payload != NULL ? S3_XML_CONTENT_TYPE : NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_delete_bucket(s3_client *client, const char *bucket)
{
    if (client == NULL || !valid_bucket(bucket)) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "DELETE", bucket, NULL, NULL, NULL, 0, NULL,
                     &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_head_bucket(s3_client *client, const char *bucket)
{
    if (client == NULL || !valid_bucket(bucket)) {
        return EINVAL;
    }
    aws_resp resp;
    int rc =
        s3_call(client, "HEAD", bucket, NULL, NULL, NULL, 0, NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_get_bucket_location(s3_client *client, const char *bucket,
                           char *region_out, size_t region_cap)
{
    if (!valid_bucket(bucket) || region_out == NULL || region_cap == 0) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "GET", bucket, NULL, "location=", NULL, 0, NULL,
                     &resp);
    if (rc != 0) {
        return rc;
    }
    char *value = xml_text(resp.body, "LocationConstraint");
    const char *region = "us-east-1";
    if (value != NULL && value[0] != '\0') {
        region = value;
    }
    size_t len = strlen(region);
    if (len >= region_cap) {
        free(value);
        aws_resp_free(&resp);
        return ENAMETOOLONG;
    }
    memcpy(region_out, region, len + 1);
    free(value);
    aws_resp_free(&resp);
    return 0;
}

/* --- bucket configuration subresources --------------------------------- */

int s3_set_versioning(s3_client *client, const char *bucket, int enabled)
{
    if (client == NULL || !valid_bucket(bucket)) {
        return EINVAL;
    }
    const char *body =
        enabled
            ? "<VersioningConfiguration "
              "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
              "<Status>Enabled</Status></VersioningConfiguration>"
            : "<VersioningConfiguration "
              "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
              "<Status>Suspended</Status></VersioningConfiguration>";
    aws_resp resp;
    int rc = s3_call(client, "PUT", bucket, NULL, "versioning=", body,
                     strlen(body), S3_XML_CONTENT_TYPE, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_get_versioning(s3_client *client, const char *bucket, int *enabled)
{
    if (!valid_bucket(bucket) || enabled == NULL) {
        return EINVAL;
    }
    aws_resp resp;
    int rc =
        s3_call(client, "GET", bucket, NULL, "versioning=", NULL, 0, NULL,
                &resp);
    if (rc != 0) {
        return rc;
    }
    char *status = xml_text(resp.body, "Status");
    *enabled = status != NULL && strcmp(status, "Enabled") == 0;
    free(status);
    aws_resp_free(&resp);
    return 0;
}

int s3_set_public_access_block(s3_client *client, const char *bucket,
                               const s3_public_access_block *block)
{
    if (client == NULL || !valid_bucket(bucket) || block == NULL) {
        return EINVAL;
    }
    char body[768];
    int n = snprintf(
        body, sizeof(body),
        "<PublicAccessBlockConfiguration "
        "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<BlockPublicAcls>%s</BlockPublicAcls>"
        "<IgnorePublicAcls>%s</IgnorePublicAcls>"
        "<BlockPublicPolicy>%s</BlockPublicPolicy>"
        "<RestrictPublicBuckets>%s</RestrictPublicBuckets>"
        "</PublicAccessBlockConfiguration>",
        block->block_public_acls ? "true" : "false",
        block->ignore_public_acls ? "true" : "false",
        block->block_public_policy ? "true" : "false",
        block->restrict_public_buckets ? "true" : "false");
    if (n < 0 || (size_t)n >= sizeof(body)) {
        return EOVERFLOW;
    }
    aws_resp resp;
    int rc = s3_call(client, "PUT", bucket, NULL, "publicAccessBlock=", body,
                     (size_t)n, S3_XML_CONTENT_TYPE, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_get_public_access_block(s3_client *client, const char *bucket,
                               s3_public_access_block *out)
{
    if (!valid_bucket(bucket) || out == NULL) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "GET", bucket, NULL, "publicAccessBlock=", NULL, 0,
                     NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    xml_bool(resp.body, "BlockPublicAcls", &out->block_public_acls);
    xml_bool(resp.body, "IgnorePublicAcls", &out->ignore_public_acls);
    xml_bool(resp.body, "BlockPublicPolicy", &out->block_public_policy);
    xml_bool(resp.body, "RestrictPublicBuckets", &out->restrict_public_buckets);
    aws_resp_free(&resp);
    return 0;
}

int s3_set_encryption(s3_client *client, const char *bucket,
                      const char *algorithm, const char *kms_key_id)
{
    if (client == NULL || !valid_bucket(bucket) || algorithm == NULL ||
        algorithm[0] == '\0') {
        return EINVAL;
    }
    char body[1024];
    size_t used = 0;
    int n = snprintf(body, sizeof(body),
                     "<ServerSideEncryptionConfiguration "
                     "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                     "<Rule><ApplyServerSideEncryptionByDefault>"
                     "<SSEAlgorithm>");
    if (n < 0 || (size_t)n >= sizeof(body)) {
        return EOVERFLOW;
    }
    used = (size_t)n;
    if (append_escaped(body, sizeof(body), &used, algorithm) != 0) {
        return EOVERFLOW;
    }
    n = snprintf(body + used, sizeof(body) - used, "</SSEAlgorithm>");
    if (n < 0 || (size_t)n >= sizeof(body) - used) {
        return EOVERFLOW;
    }
    used += (size_t)n;
    if (kms_key_id != NULL && kms_key_id[0] != '\0') {
        n = snprintf(body + used, sizeof(body) - used, "<KMSMasterKeyID>");
        if (n < 0 || (size_t)n >= sizeof(body) - used) {
            return EOVERFLOW;
        }
        used += (size_t)n;
        if (append_escaped(body, sizeof(body), &used, kms_key_id) != 0) {
            return EOVERFLOW;
        }
        n = snprintf(body + used, sizeof(body) - used, "</KMSMasterKeyID>");
        if (n < 0 || (size_t)n >= sizeof(body) - used) {
            return EOVERFLOW;
        }
        used += (size_t)n;
    }
    n = snprintf(body + used, sizeof(body) - used,
                 "</ApplyServerSideEncryptionByDefault></Rule>"
                 "</ServerSideEncryptionConfiguration>");
    if (n < 0 || (size_t)n >= sizeof(body) - used) {
        return EOVERFLOW;
    }
    used += (size_t)n;
    aws_resp resp;
    int rc = s3_call(client, "PUT", bucket, NULL, "encryption=", body, used,
                     S3_XML_CONTENT_TYPE, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_get_encryption(s3_client *client, const char *bucket,
                      char *algorithm_out, size_t algorithm_cap)
{
    if (!valid_bucket(bucket) || algorithm_out == NULL || algorithm_cap == 0) {
        return EINVAL;
    }
    aws_resp resp;
    int rc =
        s3_call(client, "GET", bucket, NULL, "encryption=", NULL, 0, NULL,
                &resp);
    if (rc != 0) {
        return rc;
    }
    char *algorithm = xml_text(resp.body, "SSEAlgorithm");
    if (algorithm == NULL) {
        aws_resp_free(&resp);
        return EIO;
    }
    size_t len = strlen(algorithm);
    if (len >= algorithm_cap) {
        free(algorithm);
        aws_resp_free(&resp);
        return ENAMETOOLONG;
    }
    memcpy(algorithm_out, algorithm, len + 1);
    free(algorithm);
    aws_resp_free(&resp);
    return 0;
}

int s3_put_lifecycle(s3_client *client, const char *bucket, const char *xml)
{
    if (client == NULL || !valid_bucket(bucket) || xml == NULL) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "PUT", bucket, NULL, "lifecycle=", xml,
                     strlen(xml), S3_XML_CONTENT_TYPE, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}

int s3_get_lifecycle(s3_client *client, const char *bucket, char **xml_out)
{
    if (!valid_bucket(bucket) || xml_out == NULL) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "GET", bucket, NULL, "lifecycle=", NULL, 0, NULL,
                     &resp);
    if (rc != 0) {
        return rc;
    }
    char *copy = malloc(resp.body_len + 1);
    if (copy == NULL) {
        aws_resp_free(&resp);
        return ENOMEM;
    }
    if (resp.body_len > 0 && resp.body != NULL) {
        memcpy(copy, resp.body, resp.body_len);
    }
    copy[resp.body_len] = '\0';
    *xml_out = copy;
    aws_resp_free(&resp);
    return 0;
}

int s3_delete_lifecycle(s3_client *client, const char *bucket)
{
    if (client == NULL || !valid_bucket(bucket)) {
        return EINVAL;
    }
    aws_resp resp;
    int rc = s3_call(client, "DELETE", bucket, NULL, "lifecycle=", NULL, 0,
                     NULL, &resp);
    if (rc != 0) {
        return rc;
    }
    aws_resp_free(&resp);
    return 0;
}
