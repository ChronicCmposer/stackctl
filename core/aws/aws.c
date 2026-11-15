/*
 * aws.c — client context: profile-only credential resolution, `AWS_*` env
 * stripping, endpoint override, retry policy helpers.
 *
 * Credentials come exclusively from $HOME/.aws/credentials; the frozen
 * core/ini interface exposes only a writer, so the read adapter lives in
 * ini_read.c (cross-tested against core/ini's writer).
 */

#include "aws_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

/* Unset every AWS_* variable so ambient exports cannot pick an identity. */
static void strip_aws_environment(void)
{
    if (environ == NULL) {
        return;
    }
    size_t count = 0;
    while (environ[count] != NULL) {
        count++;
    }
    char **names = calloc(count + 1, sizeof(*names));
    if (names == NULL) {
        return;
    }
    size_t found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strncmp(environ[i], "AWS_", 4) == 0) {
            char *equals = strchr(environ[i], '=');
            if (equals == NULL) {
                continue;
            }
            size_t name_len = (size_t)(equals - environ[i]);
            char *name = malloc(name_len + 1);
            if (name == NULL) {
                continue;
            }
            memcpy(name, environ[i], name_len);
            name[name_len] = '\0';
            names[found++] = name;
        }
    }
    for (size_t i = 0; i < found; i++) {
        unsetenv(names[i]);
        free(names[i]);
    }
    free(names);
}

int aws_init(aws_ctx **out, const char *profile_name)
{
    if (out == NULL || profile_name == NULL || *profile_name == '\0') {
        return EINVAL;
    }
    *out = NULL;

    /* Ambient AWS_* exports must never select an identity, even when the
     * credential file is missing or unreadable. Strip before any early exit. */
    strip_aws_environment();

    const char *home = getenv("HOME");
    if (home == NULL || *home == '\0') {
        return ENOENT;
    }
    char path[4096];
    int written = snprintf(path, sizeof(path), "%s/.aws/credentials", home);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return ENAMETOOLONG;
    }

    char *access = NULL;
    char *secret = NULL;
    char *token = NULL;
    int rc = aws_ini_read_profile(path, profile_name, &access, &secret,
                                  &token);
    if (rc != 0) {
        return rc;
    }

    aws_ctx *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        free(access);
        free(secret);
        free(token);
        return ENOMEM;
    }
    ctx->access_key = access;
    ctx->secret_key = secret;
    ctx->session_token = token;
    ctx->backoff_base_ms = 200;

    const char *endpoint = getenv("STACKCTL_ENDPOINT_URL");
    if (endpoint != NULL && *endpoint != '\0') {
        ctx->endpoint = strdup(endpoint);
        if (ctx->endpoint == NULL) {
            aws_free(ctx);
            return ENOMEM;
        }
        size_t elen = strlen(ctx->endpoint);
        while (elen > 0 && ctx->endpoint[elen - 1] == '/') {
            ctx->endpoint[--elen] = '\0';
        }
    }

    /* Transport (curl) is initialised lazily by http.c on first request, so
     * the context unit stays linkable without libcurl for unit tests. */

    *out = ctx;
    return 0;
}

void aws_free(aws_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->transport_teardown != NULL) {
        ctx->transport_teardown(ctx);
    }
    free(ctx->access_key);
    free(ctx->secret_key);
    free(ctx->session_token);
    free(ctx->endpoint);
    free(ctx);
}

int aws_should_retry(long status)
{
    return (status >= 500 && status <= 599) || status == 429;
}

unsigned aws_backoff_ms(unsigned base_ms, int attempt)
{
    if (base_ms == 0) {
        return 0;
    }
    int shift = attempt < 0 ? 0 : attempt;
    if (shift > 10) {
        shift = 10;
    }
    unsigned long scaled = (unsigned long)base_ms << shift;
    unsigned long jitter = (unsigned long)(rand() % (int)base_ms);
    unsigned long total = scaled + jitter;
    return total > 0xffffffffUL ? 0xffffffffU : (unsigned)total;
}

/* Locate the authority/host in a URL ("scheme://host[:port][/path]"). */
static const char *url_authority(const char *url, size_t *authority_len)
{
    const char *scheme = strstr(url, "://");
    if (scheme == NULL) {
        return NULL;
    }
    const char *authority = scheme + 3;
    const char *end = authority + strcspn(authority, "/?#");
    *authority_len = (size_t)(end - authority);
    return *authority_len == 0 ? NULL : authority;
}

int aws_build_url(const aws_ctx *ctx, const aws_req *req,
                  char **url_out, char **host_out)
{
    if (ctx == NULL || req == NULL || url_out == NULL || host_out == NULL) {
        return EINVAL;
    }
    if (req->service == NULL || req->region == NULL || req->path == NULL ||
        req->path[0] != '/') {
        return EINVAL;
    }

    const char *scheme = "https";
    char *host = NULL;
    const char *base_path = "";

    if (ctx->endpoint != NULL) {
        scheme = strncmp(ctx->endpoint, "http://", 7) == 0 ? "http" : "https";
        size_t authority_len = 0;
        const char *authority = url_authority(ctx->endpoint, &authority_len);
        if (authority == NULL) {
            return EINVAL;
        }
        host = malloc(authority_len + 1);
        if (host == NULL) {
            return ENOMEM;
        }
        memcpy(host, authority, authority_len);
        host[authority_len] = '\0';
        base_path = authority + authority_len;
    } else {
        size_t need = strlen(req->service) + strlen(req->region) +
                      sizeof(".amazonaws.com") + 2;
        host = malloc(need);
        if (host == NULL) {
            return ENOMEM;
        }
        snprintf(host, need, "%s.%s.amazonaws.com", req->service, req->region);
    }

    size_t url_len = strlen(scheme) + 3 + strlen(host) + strlen(base_path) +
                     strlen(req->path) + (req->query != NULL ? strlen(req->query) + 1 : 0) +
                     1;
    char *url = malloc(url_len);
    if (url == NULL) {
        free(host);
        return ENOMEM;
    }
    size_t used = 0;
    int n = snprintf(url, url_len, "%s://%s%s%s", scheme, host, base_path,
                     req->path);
    if (n < 0 || (size_t)n >= url_len) {
        free(host);
        free(url);
        return EOVERFLOW;
    }
    used = (size_t)n;
    if (req->query != NULL && req->query[0] != '\0') {
        n = snprintf(url + used, url_len - used, "?%s", req->query);
        if (n < 0 || (size_t)n >= url_len - used) {
            free(host);
            free(url);
            return EOVERFLOW;
        }
    }

    *url_out = url;
    *host_out = host;
    return 0;
}

void aws_test_set_backoff(aws_ctx *ctx, unsigned base_ms)
{
    if (ctx != NULL) {
        ctx->backoff_base_ms = base_ms;
    }
}
