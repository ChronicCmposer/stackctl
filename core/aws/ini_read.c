/*
 * ini_read.c — minimal reader for the subset of INI needed to load one AWS
 * credentials profile.
 *
 * `core/ini` freezes only `ini_upsert_section` (a writer); it exposes no read
 * symbol, and it is outside this lane's globs. Rather than duplicate an INI
 * parser ad hoc inside aws.c, this file is the single in-module adapter. It
 * follows core/ini's lexical rules (ASCII space/tab/CR/LF trim, `[section]`
 * headers, first `=`/`:` separator, no line continuation) and diverges only in
 * the ways AWS credential files require:
 *   - key names compare case-insensitively (AWS treats them that way);
 *   - `#`/`;` comment lines are ignored;
 *   - a missing access/secret key is ENOENT for the requested profile.
 * The divergence is cross-tested in aws_test.c against a file produced by
 * core/ini's writer, so the two modules cannot drift apart silently.
 */

#include "aws_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CRED_INI_MAX (256 * 1024)

static char *trim(char *text)
{
    while (*text != '\0' && (*text == ' ' || *text == '\t' ||
                              *text == '\r' || *text == '\n')) {
        text++;
    }
    char *end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' ||
                          end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return text;
}

static int key_is(const char *key, const char *expected)
{
    while (*key != '\0' && *expected != '\0') {
        if (tolower((unsigned char)*key) !=
            tolower((unsigned char)*expected)) {
            return 0;
        }
        key++;
        expected++;
    }
    return *key == '\0' && *expected == '\0';
}

static int assign(char **slot, const char *value)
{
    char *copy = strdup(value);
    if (copy == NULL) {
        return ENOMEM;
    }
    free(*slot);
    *slot = copy;
    return 0;
}

/* Split "key = value" / "key: value"; returns 0 when the line has no key. */
static int split_key_value(char *line, char **key_out, char **value_out)
{
    char *separator = strchr(line, '=');
    if (separator == NULL) {
        separator = strchr(line, ':');
    }
    if (separator == NULL) {
        return 0;
    }
    *separator = '\0';
    *key_out = trim(line);
    *value_out = trim(separator + 1);
    return 1;
}

static int parse_profile(char *data, const char *profile, char **access,
                         char **secret, char **token)
{
    char *cursor = data;
    int in_profile = 0;

    while (cursor != NULL && *cursor != '\0') {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');
        if (newline != NULL) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor = NULL;
        }
        line = trim(line);
        if (*line == '\0' || *line == '#' || *line == ';') {
            continue;
        }
        if (*line == '[') {
            char *close = strchr(line, ']');
            if (close == NULL) {
                continue;
            }
            *close = '\0';
            in_profile = strcmp(trim(line + 1), profile) == 0;
            continue;
        }
        if (!in_profile) {
            continue;
        }
        char *key = NULL;
        char *value = NULL;
        if (!split_key_value(line, &key, &value) || *key == '\0') {
            continue;
        }
        int rc = 0;
        if (key_is(key, "aws_access_key_id")) {
            rc = assign(access, value);
        } else if (key_is(key, "aws_secret_access_key")) {
            rc = assign(secret, value);
        } else if (key_is(key, "aws_session_token")) {
            rc = assign(token, value);
        }
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int aws_ini_read_profile(const char *path, const char *profile,
                         char **access_out, char **secret_out,
                         char **token_out)
{
    if (path == NULL || profile == NULL || access_out == NULL ||
        secret_out == NULL || token_out == NULL || *profile == '\0') {
        return EINVAL;
    }
    *access_out = NULL;
    *secret_out = NULL;
    *token_out = NULL;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return errno != 0 ? errno : ENOENT;
    }

    struct stat status;
    if (fstat(fileno(f), &status) != 0) {
        int rc = errno != 0 ? errno : EIO;
        fclose(f);
        return rc;
    }
    if (status.st_size < 0 ||
        (unsigned long long)status.st_size > (CRED_INI_MAX - 1)) {
        fclose(f);
        return EFBIG;
    }

    char *data = malloc(CRED_INI_MAX);
    if (data == NULL) {
        fclose(f);
        return ENOMEM;
    }
    size_t len = fread(data, 1, CRED_INI_MAX - 1, f);
    if (ferror(f)) {
        int rc = errno != 0 ? errno : EIO;
        fclose(f);
        free(data);
        return rc;
    }
    if (!feof(f)) {
        /* Grew past the cap between fstat and fread: refuse to truncate. */
        fclose(f);
        free(data);
        return EFBIG;
    }
    fclose(f);
    data[len] = '\0';

    char *access = NULL;
    char *secret = NULL;
    char *token = NULL;
    int rc = parse_profile(data, profile, &access, &secret, &token);
    free(data);
    if (rc == 0 && (access == NULL || secret == NULL)) {
        rc = ENOENT;
    }
    if (rc != 0) {
        free(access);
        free(secret);
        free(token);
        return rc;
    }
    *access_out = access;
    *secret_out = secret;
    *token_out = token;
    return 0;
}
