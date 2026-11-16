/*
 * http.c — libcurl adapter for the AWS request seam.
 *
 * This unit owns every libcurl symbol: it initialises/reuses the handle,
 * converts the signed header lines into a curl_slist, buffers the response, and
 * maps transport failures to errno-style codes. All signing/retry policy lives
 * in request.c (aws_http_execute), which is transport-independent.
 */

#include "aws_internal.h"

#include <curl/curl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define AWS_CONNECT_TIMEOUT_SEC 5L
#define AWS_TOTAL_TIMEOUT_SEC 30L

static void clear_headers(aws_resp *resp)
{
    for (size_t i = 0; i < resp->header_count; i++) {
        free(resp->headers[i].name);
        free(resp->headers[i].value);
    }
    free(resp->headers);
    resp->headers = NULL;
    resp->header_count = 0;
}

static int add_header(aws_resp *resp, const char *name, size_t name_len,
                      const char *value, size_t value_len)
{
    aws_header *grown = realloc(resp->headers,
                                (resp->header_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        return ENOMEM;
    }
    resp->headers = grown;
    char *name_copy = malloc(name_len + 1);
    char *value_copy = malloc(value_len + 1);
    if (name_copy == NULL || value_copy == NULL) {
        free(name_copy);
        free(value_copy);
        return ENOMEM;
    }
    memcpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';
    memcpy(value_copy, value, value_len);
    value_copy[value_len] = '\0';
    resp->headers[resp->header_count].name = name_copy;
    resp->headers[resp->header_count].value = value_copy;
    resp->header_count++;
    return 0;
}

static size_t write_body(char *data, size_t size, size_t nmemb, void *ud)
{
    aws_resp *resp = ud;
    size_t len = size * nmemb;
    if (len == 0) {
        return 0;
    }
    char *grown = realloc(resp->body, resp->body_len + len + 1);
    if (grown == NULL) {
        return 0; /* aborts the transfer with CURLE_WRITE_ERROR */
    }
    resp->body = grown;
    memcpy(resp->body + resp->body_len, data, len);
    resp->body_len += len;
    resp->body[resp->body_len] = '\0';
    return len;
}

static size_t write_header(char *data, size_t size, size_t nmemb, void *ud)
{
    aws_resp *resp = ud;
    size_t len = size * nmemb;
    if (len >= 5 && strncmp(data, "HTTP/", 5) == 0) {
        /* A new status line (redirect/100-continue) starts a fresh header set. */
        clear_headers(resp);
        return len;
    }
    const char *colon = memchr(data, ':', len);
    if (colon == NULL) {
        return len;
    }
    size_t name_len = (size_t)(colon - data);
    const char *value = colon + 1;
    size_t value_len = len - name_len - 1;
    while (value_len > 0 && (value[0] == ' ' || value[0] == '\t')) {
        value++;
        value_len--;
    }
    while (value_len > 0 &&
           (value[value_len - 1] == '\r' || value[value_len - 1] == '\n')) {
        value_len--;
    }
    if (add_header(resp, data, name_len, value, value_len) != 0) {
        return 0;
    }
    return len;
}

static int map_curl_error(CURLcode code)
{
    switch (code) {
    case CURLE_OPERATION_TIMEDOUT:
        return ETIMEDOUT;
    case CURLE_COULDNT_CONNECT:
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
        return ECONNREFUSED;
    case CURLE_GOT_NOTHING:
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_PARTIAL_FILE:
        return ECONNRESET;
    default:
        return EIO;
    }
}

static void transport_teardown(aws_ctx *ctx)
{
    if (ctx->curl != NULL) {
        curl_easy_cleanup(ctx->curl);
        ctx->curl = NULL;
    }
    /* Pair with curl_global_init(). libcurl reference-counts global state, so
     * one cleanup per context-init keeps other live contexts valid and is
     * idempotent across repeated aws_free paths. */
    if (ctx->curl_ready) {
        curl_global_cleanup();
        ctx->curl_ready = 0;
    }
}

/* Lazily create the reusable handle; http.c owns all libcurl symbols. */
static int ensure_transport(aws_ctx *ctx)
{
    if (ctx->curl_ready && ctx->curl != NULL) {
        return 0;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return EIO;
    }
    ctx->curl = curl_easy_init();
    if (ctx->curl == NULL) {
        curl_global_cleanup();
        return EIO;
    }
    ctx->curl_ready = 1;
    ctx->transport_teardown = transport_teardown;
    return 0;
}

static int curl_transport(aws_ctx *ctx, const aws_http_attempt *attempt,
                          aws_resp *resp, void *ud)
{
    (void)ud;
    struct curl_slist *headers = NULL;
    for (size_t i = 0; attempt->headers[i] != NULL; i++) {
        headers = curl_slist_append(headers, attempt->headers[i]);
        if (headers == NULL) {
            return ENOMEM;
        }
    }

    CURL *handle = ctx->curl;
    curl_easy_reset(handle);
    curl_easy_setopt(handle, CURLOPT_URL, attempt->url);
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, attempt->method);
    /*
     * CUSTOMREQUEST only rewrites the request line; curl still expects a
     * response body. S3 answers HEAD with "Transfer-Encoding: chunked" and
     * no body, so without NOBODY curl blocks on the keep-alive connection
     * until the total timeout. NOBODY makes curl stop after the headers,
     * which is the correct HEAD semantics (same as curl -I).
     */
    if (strcmp(attempt->method, "HEAD") == 0) {
        curl_easy_setopt(handle, CURLOPT_NOBODY, 1L);
    }
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, write_header);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, resp);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, AWS_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, AWS_TOTAL_TIMEOUT_SEC);
    if (attempt->body != NULL && attempt->body_len > 0) {
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, attempt->body);
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)attempt->body_len);
    }

    CURLcode perform = curl_easy_perform(handle);
    curl_slist_free_all(headers);

    if (perform != CURLE_OK) {
        clear_headers(resp);
        return map_curl_error(perform);
    }
    long status = 0;
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    resp->status = status;
    return 0;
}

int aws_request(aws_ctx *ctx, const aws_req *req, aws_resp *resp)
{
    if (ctx == NULL) {
        return EINVAL;
    }
    int rc = ensure_transport(ctx);
    if (rc != 0) {
        return rc;
    }
    return aws_http_execute(ctx, req, resp, curl_transport, NULL);
}
