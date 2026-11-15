#define _GNU_SOURCE
/*
 * resp.c — response ownership, header lookup, lazy JSON parsing, AWS error-code
 * extraction and clock-skew diagnosis.
 */

#include "aws_internal.h"
#include "yyjson.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

void aws_resp_free(aws_resp *resp)
{
    if (resp == NULL) {
        return;
    }
    for (size_t i = 0; i < resp->header_count; i++) {
        free(resp->headers[i].name);
        free(resp->headers[i].value);
    }
    free(resp->headers);
    free(resp->body);
    if (resp->json != NULL) {
        yyjson_doc_free(resp->json);
    }
    memset(resp, 0, sizeof(*resp));
}

const char *aws_resp_header(const aws_resp *resp, const char *name)
{
    if (resp == NULL || name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < resp->header_count; i++) {
        if (strcasecmp(resp->headers[i].name, name) == 0) {
            return resp->headers[i].value;
        }
    }
    return NULL;
}

struct yyjson_doc *aws_resp_json(aws_resp *resp)
{
    if (resp == NULL) {
        return NULL;
    }
    if (resp->json != NULL) {
        return resp->json;
    }
    if (resp->body == NULL || resp->body_len == 0) {
        return NULL;
    }
    resp->json = yyjson_read(resp->body, resp->body_len, 0);
    return resp->json;
}

/* Copy `text` to `out`, reducing a namespace prefix (`ns#Name`) to `Name`. */
static void copy_code(const char *text, char out[AWS_ERROR_CODE_LEN])
{
    const char *name = strrchr(text, '#');
    name = name != NULL ? name + 1 : text;
    size_t len = strlen(name);
    if (len >= AWS_ERROR_CODE_LEN) {
        len = AWS_ERROR_CODE_LEN - 1;
    }
    memcpy(out, name, len);
    out[len] = '\0';
}

static int code_from_json(aws_resp *resp, char out[AWS_ERROR_CODE_LEN])
{
    yyjson_doc *doc = aws_resp_json(resp);
    if (doc == NULL) {
        return 0;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        return 0;
    }
    yyjson_val *value = yyjson_obj_get(root, "__type");
    if (value == NULL) {
        value = yyjson_obj_get(root, "Code");
    }
    if (value == NULL) {
        value = yyjson_obj_get(root, "code");
    }
    if (value == NULL || !yyjson_is_str(value)) {
        return 0;
    }
    copy_code(yyjson_get_str(value), out);
    return 1;
}

static int code_from_xml(const aws_resp *resp, char out[AWS_ERROR_CODE_LEN])
{
    const char *open = strstr(resp->body, "<Code>");
    if (open == NULL) {
        return 0;
    }
    open += strlen("<Code>");
    const char *close = strstr(open, "</Code>");
    if (close == NULL || close <= open) {
        return 0;
    }
    size_t len = (size_t)(close - open);
    if (len >= AWS_ERROR_CODE_LEN) {
        len = AWS_ERROR_CODE_LEN - 1;
    }
    memcpy(out, open, len);
    out[len] = '\0';
    return 1;
}

int aws_error_code(const aws_resp *resp, char out[AWS_ERROR_CODE_LEN])
{
    if (resp == NULL || out == NULL) {
        return -EINVAL;
    }
    out[0] = '\0';
    if (resp->body == NULL || resp->body_len == 0) {
        return 0;
    }
    /* aws_resp_json caches; cast away const because caching mutates the
     * response object by design. */
    if (code_from_json((aws_resp *)resp, out)) {
        return 1;
    }
    if (code_from_xml(resp, out)) {
        return 1;
    }
    return 0;
}

static int clock_skew_code(const char *code)
{
    /* InvalidSignatureException/signature mismatch means a wrong secret or bad
     * signing, not a skewed clock; only genuine skew codes qualify. */
    return strcmp(code, "RequestTimeTooSkewed") == 0 ||
           strcmp(code, "RequestExpired") == 0;
}

static int parse_http_date(const char *value, time_t *out)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    char *end = strptime(value, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (end == NULL) {
        end = strptime(value, "%a, %d %b %Y %H:%M:%S", &tm);
    }
    if (end == NULL) {
        return -1;
    }
    *out = timegm(&tm);
    return 0;
}

int aws_clock_skew(const aws_resp *resp, long *delta_sec)
{
    if (resp == NULL || delta_sec == NULL) {
        return -EINVAL;
    }
    if (resp->status != 403) {
        return 0;
    }
    char code[AWS_ERROR_CODE_LEN];
    if (aws_error_code(resp, code) != 1 || !clock_skew_code(code)) {
        return 0;
    }
    const char *date = aws_resp_header(resp, "Date");
    time_t server_time = 0;
    if (date == NULL || parse_http_date(date, &server_time) != 0) {
        return 0;
    }
    *delta_sec = (long)(time(NULL) - server_time);
    return 1;
}
