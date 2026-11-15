/*
 * instance_util.c — pure, side-effect-free helpers shared by the instance
 * verbs: base64, host-key fingerprints, release-manifest selection, arch/type
 * resolution, state classification and small string utilities.
 *
 * Nothing here touches the network, the filesystem (except the CSPRNG) or
 * global state; every function is directly unit-testable.
 */

#include "instance.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/crypto/crypto.h"

/* ------------------------------------------------------------------------- */
/* Base64                                                                    */
/* ------------------------------------------------------------------------- */

static const char base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int instance_base64_encode(const unsigned char *data, size_t len, char *out,
                           size_t out_size) {
    size_t need;
    size_t in = 0;
    size_t pos = 0;

    if (out == NULL || (data == NULL && len != 0)) {
        return EINVAL;
    }
    need = ((len + 2) / 3) * 4;
    if (out_size < need + 1) {
        return ENAMETOOLONG;
    }
    while (in + 2 < len) {
        uint32_t triple = ((uint32_t)data[in] << 16) |
                          ((uint32_t)data[in + 1] << 8) | data[in + 2];
        out[pos++] = base64_alphabet[(triple >> 18) & 0x3f];
        out[pos++] = base64_alphabet[(triple >> 12) & 0x3f];
        out[pos++] = base64_alphabet[(triple >> 6) & 0x3f];
        out[pos++] = base64_alphabet[triple & 0x3f];
        in += 3;
    }
    if (in < len) {
        uint32_t triple = (uint32_t)data[in] << 16;
        int remaining = (int)(len - in);
        if (remaining == 2) {
            triple |= (uint32_t)data[in + 1] << 8;
        }
        out[pos++] = base64_alphabet[(triple >> 18) & 0x3f];
        out[pos++] = base64_alphabet[(triple >> 12) & 0x3f];
        out[pos++] = remaining == 2 ? base64_alphabet[(triple >> 6) & 0x3f]
                                    : '=';
        out[pos++] = '=';
    }
    out[pos] = '\0';
    return 0;
}

static int base64_value(char c) {
    const char *found;

    if (c == '=') {
        return -2;
    }
    found = strchr(base64_alphabet, c);
    if (found == NULL) {
        return -1;
    }
    return (int)(found - base64_alphabet);
}

int instance_base64_decode(const char *text, unsigned char *out, size_t out_size,
                           size_t *out_len) {
    size_t pos = 0;
    int quad[4];
    int quad_count = 0;

    if (text == NULL || out == NULL || out_len == NULL) {
        return EINVAL;
    }
    *out_len = 0;
    for (const char *cursor = text; *cursor != '\0'; cursor++) {
        int value;
        int pad = 0;

        if (isspace((unsigned char)*cursor)) {
            continue;
        }
        value = base64_value(*cursor);
        if (value == -1) {
            return EINVAL;
        }
        if (value == -2) {
            pad = 1;
            value = 0;
        }
        quad[quad_count++] = pad != 0 ? -1 : value;
        if (quad_count == 4) {
            size_t produce = 3;
            uint32_t triple;

            if (quad[3] == -1) {
                produce = 2;
            }
            if (quad[2] == -1) {
                produce = 1;
            }
            if (quad[2] == -1 && quad[3] != -1) {
                return EINVAL;
            }
            triple = ((uint32_t)quad[0] << 18) | ((uint32_t)quad[1] << 12) |
                     ((uint32_t)(quad[2] == -1 ? 0 : quad[2]) << 6) |
                     (uint32_t)(quad[3] == -1 ? 0 : quad[3]);
            if (pos + produce > out_size) {
                return ENAMETOOLONG;
            }
            out[pos++] = (unsigned char)((triple >> 16) & 0xff);
            if (produce >= 2) {
                out[pos++] = (unsigned char)((triple >> 8) & 0xff);
            }
            if (produce >= 3) {
                out[pos++] = (unsigned char)(triple & 0xff);
            }
            quad_count = 0;
            if (quad[2] == -1 || quad[3] == -1) {
                break; /* padding ends the stream */
            }
        }
    }
    if (quad_count != 0) {
        return EINVAL;
    }
    *out_len = pos;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Host-key fingerprints                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Split an ssh-keyscan line into key type and base64 blob. Accepts both
 * `<host> <type> <blob>` and `<type> <blob>` shapes.
 */
static int split_key_line(const char *line, const char **type,
                          const char **blob) {
    const char *tokens[3] = {NULL, NULL, NULL};
    size_t count = 0;
    const char *cursor = line;

    if (line == NULL) {
        return EINVAL;
    }
    while (*cursor != '\0' && count < 3) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' ||
               *cursor == '\n') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        tokens[count++] = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\r' && *cursor != '\n') {
            cursor++;
        }
    }
    if (count < 2) {
        return EINVAL;
    }
    if (strncmp(tokens[0], "ssh-", 4) == 0 ||
        strncmp(tokens[0], "ecdsa-", 6) == 0 ||
        strncmp(tokens[0], "sk-", 3) == 0) {
        *type = tokens[0];
        *blob = tokens[1];
    } else {
        if (count < 3) {
            return EINVAL;
        }
        *type = tokens[1];
        *blob = tokens[2];
    }
    return 0;
}

int instance_key_fingerprint(const char *key_line, char *out, size_t out_size) {
    const char *type;
    const char *blob;
    unsigned char decoded[1024];
    size_t decoded_len = 0;
    uint8_t digest[CRYPTO_SHA256_DIGEST_LEN];
    char encoded[64];
    size_t encoded_len;
    int rc;

    (void)type;
    if (out == NULL) {
        return EINVAL;
    }
    rc = split_key_line(key_line, &type, &blob);
    if (rc != 0) {
        return rc;
    }
    rc = instance_base64_decode(blob, decoded, sizeof decoded, &decoded_len);
    if (rc != 0) {
        return rc;
    }
    crypto_sha256(decoded, decoded_len, digest);
    rc = instance_base64_encode(digest, sizeof digest, encoded, sizeof encoded);
    if (rc != 0) {
        return rc;
    }
    encoded_len = strlen(encoded);
    while (encoded_len > 0 && encoded[encoded_len - 1] == '=') {
        encoded[--encoded_len] = '\0';
    }
    if (strlen("SHA256:") + encoded_len + 1 > out_size) {
        return ENAMETOOLONG;
    }
    memcpy(out, "SHA256:", 7);
    memcpy(out + 7, encoded, encoded_len + 1);
    return 0;
}

int instance_console_fingerprints(
    const char *console, char fingerprints[][INST_FINGERPRINT_MAX], size_t max,
    size_t *count) {
    const char *cursor;
    size_t stored = 0;

    if (count == NULL) {
        return EINVAL;
    }
    *count = 0;
    if (console == NULL) {
        return 0;
    }
    cursor = console;
    while ((cursor = strstr(cursor, "SHA256:")) != NULL) {
        const char *start = cursor;
        const char *end = cursor + 7;

        while (*end != '\0' &&
               (isalnum((unsigned char)*end) || *end == '+' || *end == '/' ||
                *end == '=')) {
            end++;
        }
        if (end > start + 7 && stored < max) {
            size_t len = (size_t)(end - start);

            if (len + 1 > INST_FINGERPRINT_MAX) {
                return ENAMETOOLONG;
            }
            memcpy(fingerprints[stored], start, len);
            fingerprints[stored][len] = '\0';
            stored++;
        }
        cursor = end;
    }
    *count = stored;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Release manifest                                                          */
/* ------------------------------------------------------------------------- */

static int token_matches(const char *member, const char *token) {
    const char *cursor = member;

    if (token == NULL || token[0] == '\0') {
        return 0;
    }
    while (*cursor != '\0') {
        const char *start;
        size_t len;

        while (*cursor != '\0' &&
               (*cursor == '-' || *cursor == '.' || *cursor == '_' ||
                *cursor == '/')) {
            cursor++;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != '-' && *cursor != '.' &&
               *cursor != '_' && *cursor != '/') {
            cursor++;
        }
        len = (size_t)(cursor - start);
        if (len == strlen(token) && strncmp(start, token, len) == 0) {
            return 1;
        }
    }
    return 0;
}

int instance_manifest_select(const char *manifest, const char *variant,
                             const char *arch, char *member, size_t member_size,
                             char *sha256_hex, size_t sha_size, char *choices,
                             size_t choices_size) {
    char picked_member[512] = {0};
    char picked_sha[INST_SHA_MAX] = {0};
    size_t matches = 0;
    const char *line;

    if (manifest == NULL || arch == NULL || member == NULL ||
        sha256_hex == NULL) {
        return EINVAL;
    }
    member[0] = '\0';
    sha256_hex[0] = '\0';
    if (choices != NULL && choices_size > 0) {
        choices[0] = '\0';
    }
    line = manifest;
    while (*line != '\0') {
        char copy[1024];
        const char *newline = strchr(line, '\n');
        size_t len = newline != NULL ? (size_t)(newline - line) : strlen(line);
        char *sha;
        char *name;
        char *save = NULL;

        if (len >= sizeof copy) {
            return ENAMETOOLONG;
        }
        memcpy(copy, line, len);
        copy[len] = '\0';
        sha = strtok_r(copy, " \t\r", &save);
        name = strtok_r(NULL, " \t\r", &save);
        if (sha != NULL && name != NULL && token_matches(name, arch) &&
            (variant == NULL || token_matches(name, variant))) {
            if (matches == 0) {
                if (strlen(name) + 1 > sizeof picked_member ||
                    strlen(sha) + 1 > sizeof picked_sha) {
                    return ENAMETOOLONG;
                }
                memcpy(picked_member, name, strlen(name) + 1);
                memcpy(picked_sha, sha, strlen(sha) + 1);
            }
            if (choices != NULL && choices_size > 0) {
                size_t used = strlen(choices);

                if (used < choices_size) {
                    (void)snprintf(choices + used, choices_size - used, "%s%s",
                                   used > 0 ? ", " : "", name);
                }
            }
            matches++;
        }
        if (newline == NULL) {
            break;
        }
        line = newline + 1;
    }
    if (matches == 0) {
        return ENOENT;
    }
    if (matches > 1) {
        return EINVAL; /* ambiguous; choices names every candidate */
    }
    if (strlen(picked_member) + 1 > member_size ||
        strlen(picked_sha) + 1 > sha_size) {
        return ENAMETOOLONG;
    }
    memcpy(member, picked_member, strlen(picked_member) + 1);
    memcpy(sha256_hex, picked_sha, strlen(picked_sha) + 1);
    return 0;
}

int instance_tool_available(const char *name) {
    const char *path;
    const char *start;

    if (name == NULL || name[0] == '\0' || strchr(name, '/') != NULL) {
        return 0;
    }
    path = getenv("PATH");
    if (path == NULL) {
        return 0;
    }
    start = path;
    for (;;) {
        const char *end = strchr(start, ':');
        size_t dir_len = end != NULL ? (size_t)(end - start) : strlen(start);
        char candidate[PATH_MAX];
        struct stat info;
        int written;

        if (dir_len == 0) {
            written = snprintf(candidate, sizeof candidate, "./%s", name);
        } else {
            written = snprintf(candidate, sizeof candidate, "%.*s/%s",
                               (int)dir_len, start, name);
        }
        if (written > 0 && (size_t)written < sizeof candidate &&
            stat(candidate, &info) == 0 && S_ISREG(info.st_mode) &&
            access(candidate, X_OK) == 0) {
            return 1;
        }
        if (end == NULL) {
            break;
        }
        start = end + 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Arch and instance type                                                    */
/* ------------------------------------------------------------------------- */

static int valid_arch(const char *arch) {
    return arch != NULL &&
           (strcmp(arch, "amd64") == 0 || strcmp(arch, "arm64") == 0);
}

int instance_select_arch(const char *config_arch, const char *flag_arch,
                         char *out, size_t out_size, const char **why) {
    const char *reason = NULL;
    const char *chosen = NULL;

    if (why != NULL) {
        *why = NULL;
    }
    if (out == NULL || config_arch == NULL) {
        return EINVAL;
    }
    if (strcmp(config_arch, "both") == 0) {
        if (flag_arch == NULL) {
            reason = "ARCH=both requires --arch amd64|arm64";
        } else if (!valid_arch(flag_arch)) {
            reason = "--arch must be amd64 or arm64";
        } else {
            chosen = flag_arch;
        }
    } else if (!valid_arch(config_arch)) {
        reason = "invalid ARCH in config";
    } else if (flag_arch != NULL && strcmp(flag_arch, config_arch) != 0) {
        reason = "--arch does not match the single-valued ARCH";
    } else {
        chosen = config_arch;
    }
    if (chosen == NULL) {
        if (why != NULL) {
            *why = reason;
        }
        return EINVAL;
    }
    if (strlen(chosen) + 1 > out_size) {
        return ENAMETOOLONG;
    }
    memcpy(out, chosen, strlen(chosen) + 1);
    return 0;
}

int instance_resolve_type(const instance_config *cfg, const char *arch,
                          const char *type, char *out, size_t out_size) {
    const char *list;
    const char *cursor;
    int found = 0;

    if (cfg == NULL || arch == NULL || out == NULL) {
        return EINVAL;
    }
    list = strcmp(arch, "arm64") == 0 ? cfg->instance_types_arm64
                                      : cfg->instance_types_amd64;
    if (list[0] == '\0') {
        return EINVAL;
    }
    cursor = list;
    while (*cursor != '\0' && !found) {
        const char *start;
        const char *end;
        size_t len;

        while (*cursor == ' ' || *cursor == ',' || *cursor == '\t') {
            cursor++;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != ',') {
            cursor++;
        }
        end = cursor;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        len = (size_t)(end - start);
        if (len == 0) {
            continue;
        }
        if (type == NULL) {
            found = 1;
        } else if (strlen(type) == len && strncmp(start, type, len) == 0) {
            found = 1;
        }
        if (found) {
            if (len + 1 > out_size) {
                return ENAMETOOLONG;
            }
            memcpy(out, start, len);
            out[len] = '\0';
            return 0;
        }
    }
    return EINVAL;
}

/* ------------------------------------------------------------------------- */
/* State classification and misc                                             */
/* ------------------------------------------------------------------------- */

bool instance_state_active(const char *state) {
    if (state == NULL) {
        return false;
    }
    return strcmp(state, "pending") == 0 || strcmp(state, "running") == 0 ||
           strcmp(state, "stopping") == 0 || strcmp(state, "stopped") == 0;
}

bool instance_state_terminable(const char *state) {
    if (instance_state_active(state)) {
        return true;
    }
    return state != NULL && strcmp(state, "shutting-down") == 0;
}

int instance_parse_seconds(const char *text, int *out) {
    char *end = NULL;
    long value;

    if (text == NULL || out == NULL || text[0] == '\0') {
        return EINVAL;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 0 ||
        value > INT_MAX) {
        return EINVAL;
    }
    *out = (int)value;
    return 0;
}

int instance_fqdn(const char *host, const char *domain, char *out,
                  size_t out_size) {
    if (host == NULL || domain == NULL || out == NULL || host[0] == '\0') {
        return EINVAL;
    }
    if (strchr(host, '.') != NULL) {
        if (strlen(host) + 1 > out_size) {
            return ENAMETOOLONG;
        }
        memcpy(out, host, strlen(host) + 1);
        return 0;
    }
    if (strlen(host) + strlen(domain) + 2 > out_size) {
        return ENAMETOOLONG;
    }
    memcpy(out, host, strlen(host));
    out[strlen(host)] = '.';
    memcpy(out + strlen(host) + 1, domain, strlen(domain) + 1);
    return 0;
}

int instance_client_token(const char *project, const char *nonce, char out[65]) {
    char buffer[INST_PROJECT_MAX + 80];
    uint8_t digest[CRYPTO_SHA256_DIGEST_LEN];
    static const char hex[] = "0123456789abcdef";
    int written;

    if (project == NULL || nonce == NULL || out == NULL) {
        return EINVAL;
    }
    written = snprintf(buffer, sizeof buffer, "%s:%s", project, nonce);
    if (written < 0 || (size_t)written >= sizeof buffer) {
        return ENAMETOOLONG;
    }
    crypto_sha256(buffer, (size_t)written, digest);
    for (size_t i = 0; i < sizeof digest; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
    return 0;
}

int instance_nonce(char out[33]) {
    unsigned char raw[16];
    int fd;
    ssize_t got;

    if (out == NULL) {
        return EINVAL;
    }
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return errno != 0 ? errno : EIO;
    }
    got = read(fd, raw, sizeof raw);
    close(fd);
    if (got != (ssize_t)sizeof raw) {
        return EIO;
    }
    for (size_t i = 0; i < sizeof raw; i++) {
        static const char hex[] = "0123456789abcdef";
        out[i * 2] = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0x0f];
    }
    out[32] = '\0';
    return 0;
}

const char *instance_restore_ip(const char *snapshot_ip,
                                const ec2_instance_list *list) {
    if (snapshot_ip == NULL || snapshot_ip[0] == '\0' || list == NULL) {
        return "0.0.0.0";
    }
    for (size_t i = 0; i < list->count; i++) {
        const ec2_instance *instance = &list->items[i];

        if (strcmp(instance->public_ip, snapshot_ip) == 0 &&
            (strcmp(instance->state, "running") == 0 ||
             strcmp(instance->state, "pending") == 0)) {
            return snapshot_ip;
        }
    }
    return "0.0.0.0";
}

const ec2_instance *instance_find(const ec2_instance_list *list,
                                  const char *instance_id) {
    if (list == NULL || instance_id == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].instance_id, instance_id) == 0) {
            return &list->items[i];
        }
    }
    return NULL;
}
