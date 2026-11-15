/*
 * knownhosts.c — dedicated known-hosts store (spec §8).
 *
 * Entries are keyed by `HostKeyAlias=<instance-id>` (the alias replaces the
 * host field), so SSH always targets the public IP but the store is addressed
 * by instance identity. A changed key for an already-pinned instance-id is a
 * hard error and is never rewritten.
 */

#include "knownhosts.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char *dup_string(const char *text) {
    size_t len = strlen(text);
    char *copy = malloc(len + 1);

    if (copy != NULL) {
        memcpy(copy, text, len + 1);
    }
    return copy;
}

static const char *skip_space(const char *text) {
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
        text++;
    }
    return text;
}

static int read_all(const char *path, char **out) {
    int fd = open(path, O_RDONLY);
    struct stat st;
    char *data;
    size_t total = 0;

    if (fd < 0) {
        if (errno == ENOENT) {
            *out = dup_string("");
            return *out == NULL ? ENOMEM : 0;
        }
        return errno;
    }
    if (fstat(fd, &st) != 0) {
        int rc = errno;

        close(fd);
        return rc;
    }
    if (st.st_size < 0) {
        close(fd);
        return EIO;
    }
    data = malloc((size_t)st.st_size + 1);
    if (data == NULL) {
        close(fd);
        return ENOMEM;
    }
    while (total < (size_t)st.st_size) {
        ssize_t got = read(fd, data + total, (size_t)st.st_size - total);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(data);
            close(fd);
            return errno;
        }
        if (got == 0) {
            break;
        }
        total += (size_t)got;
    }
    close(fd);
    data[total] = '\0';
    *out = data;
    return 0;
}

static int write_all(int fd, const char *data, size_t len) {
    size_t written = 0;

    while (written < len) {
        ssize_t rc = write(fd, data + written, len - written);

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        written += (size_t)rc;
    }
    return 0;
}

static int atomic_write(const char *path, const char *data, size_t len) {
    char *dircopy = dup_string(path);
    char *slash;
    char *temp;
    size_t need;
    int fd;
    int rc = 0;

    if (dircopy == NULL) {
        return ENOMEM;
    }
    slash = strrchr(dircopy, '/');
    if (slash == NULL) {
        free(dircopy);
        dircopy = dup_string(".");
        if (dircopy == NULL) {
            return ENOMEM;
        }
    } else if (slash == dircopy) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    need = strlen(dircopy) + sizeof("/.kh.tmp.XXXXXX") + 1;
    temp = malloc(need);
    if (temp == NULL) {
        free(dircopy);
        return ENOMEM;
    }
    snprintf(temp, need, "%s/.kh.tmp.XXXXXX", dircopy);
    fd = mkstemp(temp);
    if (fd < 0) {
        rc = errno;
        free(temp);
        free(dircopy);
        return rc;
    }
    if (fchmod(fd, 0600) != 0) {
        rc = errno;
    }
    if (rc == 0 && write_all(fd, data, len) != 0) {
        rc = errno;
    }
    if (rc == 0 && fsync(fd) != 0) {
        rc = errno;
    }
    if (close(fd) != 0 && rc == 0) {
        rc = errno;
    }
    if (rc == 0 && rename(temp, path) != 0) {
        rc = errno;
    }
    if (rc != 0) {
        unlink(temp);
    }
    free(temp);
    free(dircopy);
    return rc;
}

/* Split a line in place: *field receives the first whitespace-delimited token
 * and the return value is the (trimmed) remainder, or NULL when the line has
 * no remainder. */
static char *split_first(char *line, char **field) {
    char *cursor = line;

    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    *field = cursor;
    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
           *cursor != '\r' && *cursor != '\n') {
        cursor++;
    }
    if (*cursor == '\0') {
        return NULL;
    }
    *cursor = '\0';
    cursor++;
    cursor = (char *)skip_space(cursor);
    return *cursor == '\0' ? NULL : cursor;
}

/* True iff the first whitespace-delimited field of `line` equals
 * `instance_id`. Unlike split_first(), this never writes to `line`, so the
 * caller can still copy the entry byte-for-byte. */
static int line_first_field_is(const char *line, const char *instance_id) {
    const char *cursor = line;
    size_t id_len = strlen(instance_id);

    while (*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if (strncmp(cursor, instance_id, id_len) != 0) {
        return 0;
    }
    cursor += id_len;
    return *cursor == '\0' || *cursor == ' ' || *cursor == '\t' ||
           *cursor == '\r' || *cursor == '\n';
}

static int valid_instance_id(const char *instance_id) {
    if (instance_id == NULL || instance_id[0] == '\0') {
        return 0;
    }
    for (const char *cursor = instance_id; *cursor != '\0'; cursor++) {
        if (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' ||
            *cursor == '\r') {
            return 0;
        }
    }
    return 1;
}

/* Normalize an ssh-keyscan line to `<instance-id> <key material>`. */
static int normalize_key_line(const char *instance_id, const char *scanned,
                              char **out) {
    char *copy = dup_string(scanned);
    char *field = NULL;
    char *remainder;
    char *result;
    size_t need;

    if (copy == NULL) {
        return ENOMEM;
    }
    remainder = split_first(copy, &field);
    (void)field;
    if (remainder == NULL) {
        free(copy);
        return EINVAL;
    }
    {
        /* The remainder must contain at least a key type and key material. */
        char *check = dup_string(remainder);
        char *second = NULL;
        char *second_remainder;

        if (check == NULL) {
            free(copy);
            return ENOMEM;
        }
        second_remainder = split_first(check, &second);
        (void)second;
        free(check);
        if (second_remainder == NULL) {
            free(copy);
            return EINVAL;
        }
    }
    need = strlen(instance_id) + strlen(remainder) + 2;
    result = malloc(need);
    if (result == NULL) {
        free(copy);
        return ENOMEM;
    }
    snprintf(result, need, "%s %s", instance_id, remainder);
    free(copy);
    *out = result;
    return 0;
}

int kh_pin(const char *store_path, const char *instance_id,
           const char *scanned_key_line) {
    char *wanted = NULL;
    char *data = NULL;
    char *mutable;
    char *cursor;
    int found_conflict = 0;
    int found_same = 0;
    int rc;

    if (store_path == NULL || store_path[0] == '\0' ||
        !valid_instance_id(instance_id) || scanned_key_line == NULL) {
        return EINVAL;
    }
    rc = normalize_key_line(instance_id, scanned_key_line, &wanted);
    if (rc != 0) {
        return rc;
    }
    rc = read_all(store_path, &data);
    if (rc != 0) {
        free(wanted);
        return rc;
    }
    mutable = dup_string(data);
    if (mutable == NULL) {
        free(wanted);
        free(data);
        return ENOMEM;
    }
    cursor = mutable;
    while (*cursor != '\0') {
        char *newline = strchr(cursor, '\n');
        char *first = NULL;
        char *remainder;

        if (newline != NULL) {
            *newline = '\0';
        }
        remainder = split_first(cursor, &first);
        if (first != NULL && strcmp(first, instance_id) == 0) {
            const char *wanted_rest = strchr(wanted, ' ');

            wanted_rest = wanted_rest == NULL ? wanted : wanted_rest + 1;
            if (remainder != NULL && strcmp(remainder, wanted_rest) == 0) {
                found_same = 1;
            } else {
                found_conflict = 1;
            }
        }
        if (newline == NULL) {
            break;
        }
        cursor = newline + 1;
    }
    free(mutable);
    if (found_conflict) {
        free(wanted);
        free(data);
        return EPERM;
    }
    if (found_same) {
        free(wanted);
        free(data);
        return 0;
    }
    {
        size_t old_len = strlen(data);
        size_t add_len = strlen(wanted);
        size_t need = old_len + add_len + 2;
        char *content = malloc(need);
        size_t used = 0;

        if (content == NULL) {
            free(wanted);
            free(data);
            return ENOMEM;
        }
        if (old_len > 0) {
            memcpy(content, data, old_len);
            used = old_len;
            if (content[used - 1] != '\n') {
                content[used++] = '\n';
            }
        }
        memcpy(content + used, wanted, add_len);
        used += add_len;
        content[used++] = '\n';
        rc = atomic_write(store_path, content, used);
        free(content);
    }
    free(wanted);
    free(data);
    return rc;
}

bool kh_bound(const char *store_path, const char *instance_id) {
    char *data = NULL;
    char *mutable;
    char *cursor;
    bool bound = false;

    if (store_path == NULL || !valid_instance_id(instance_id)) {
        return false;
    }
    if (read_all(store_path, &data) != 0) {
        return false;
    }
    mutable = dup_string(data);
    free(data);
    if (mutable == NULL) {
        return false;
    }
    cursor = mutable;
    while (*cursor != '\0') {
        char *newline = strchr(cursor, '\n');
        char *first = NULL;

        if (newline != NULL) {
            *newline = '\0';
        }
        (void)split_first(cursor, &first);
        if (first != NULL && strcmp(first, instance_id) == 0) {
            bound = true;
            break;
        }
        if (newline == NULL) {
            break;
        }
        cursor = newline + 1;
    }
    free(mutable);
    return bound;
}

int kh_forget(const char *store_path, const char *instance_id) {
    char *data = NULL;
    char *mutable;
    char *cursor;
    char *content;
    size_t used = 0;
    int rc;

    if (store_path == NULL || !valid_instance_id(instance_id)) {
        return EINVAL;
    }
    rc = read_all(store_path, &data);
    if (rc != 0) {
        return rc;
    }
    if (data[0] == '\0') {
        free(data);
        return 0;
    }
    mutable = dup_string(data);
    if (mutable == NULL) {
        free(data);
        return ENOMEM;
    }
    content = malloc(strlen(data) + 2);
    if (content == NULL) {
        free(mutable);
        free(data);
        return ENOMEM;
    }
    cursor = mutable;
    while (*cursor != '\0') {
        char *newline = strchr(cursor, '\n');
        int drop;

        if (newline != NULL) {
            *newline = '\0';
        }
        /* Match without mutating `cursor`: the whole line must be copied
         * verbatim when retained, not just its first field. */
        drop = line_first_field_is(cursor, instance_id);
        if (!drop && cursor[0] != '\0') {
            size_t len = strlen(cursor);

            memcpy(content + used, cursor, len);
            used += len;
            content[used++] = '\n';
        }
        if (newline == NULL) {
            break;
        }
        cursor = newline + 1;
    }
    content[used] = '\0';
    rc = atomic_write(store_path, content, used);
    free(content);
    free(mutable);
    free(data);
    return rc;
}
