/*
 * ddns_curl.c — libcurl implementation of the ddns_http_ops seam (spec §5.7).
 *
 * A deliberately small HTTPS GET: fixed response buffer, redirects followed,
 * bounded connect/total timeouts, TLS verification left at libcurl defaults.
 * The update URL contains the DDNS password, so it is never logged here.
 */

#include "ddns_internal.h"

#include <curl/curl.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

struct write_ctx {
    char *body;
    size_t cap;
    size_t len;
    bool overflow;
};

static size_t write_callback(char *data, size_t size, size_t nmemb,
                             void *userdata) {
    struct write_ctx *ctx = userdata;
    size_t total = size * nmemb;

    if (ctx->overflow || ctx->len >= ctx->cap) {
        ctx->overflow = true;
        return 0;
    }
    if (total > ctx->cap - 1 - ctx->len) {
        ctx->overflow = true;
        return 0;
    }

    memcpy(ctx->body + ctx->len, data, total);
    ctx->len += total;
    return total;
}

static int curl_get(void *ud, const char *url, char *body, size_t cap,
                    size_t *len, long *status) {
    (void)ud;
    if (url == NULL || body == NULL || len == NULL || status == NULL ||
        cap == 0) {
        return EINVAL;
    }
    *len = 0;
    *status = 0;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return EIO;
    }

    CURL *handle = curl_easy_init();

    if (handle == NULL) {
        curl_global_cleanup();
        return ENOMEM;
    }

    struct write_ctx ctx = {
        .body = body,
        .cap = cap,
        .len = 0,
        .overflow = false,
    };

    body[0] = '\0';

    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_USERAGENT, "stackctl/1");
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode result = curl_easy_perform(handle);
    long response_code = 0;

    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_cleanup(handle);
    curl_global_cleanup();

    if (ctx.overflow) {
        return EOVERFLOW;
    }
    if (result != CURLE_OK) {
        return EIO;
    }

    body[ctx.len] = '\0';
    *len = ctx.len;
    *status = response_code;
    return 0;
}

const ddns_http_ops *ddns_curl_ops(void) {
    static const ddns_http_ops ops = {
        .get = curl_get,
    };
    return &ops;
}
