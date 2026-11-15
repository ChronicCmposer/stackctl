/*
 * ini.c — stackctl `~/.aws/credentials` upsert (spec §2).
 *
 * Pure text transformer: read the target, replace/insert exactly one key in
 * exactly one section, leave every other byte alone, snapshot the old file to
 * a timestamped 0600 backup, then atomically replace the target via a
 * same-directory temp file and rename(2).
 */

#include "ini.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} strbuf;

static int buf_reserve(strbuf *buf, size_t extra) {
    size_t need = buf->len + extra + 1;
    size_t cap;
    char *grown;

    if (need <= buf->cap) {
        return 0;
    }
    cap = buf->cap == 0 ? 256 : buf->cap;
    while (cap < need) {
        if (cap > ((size_t)-1) / 2) {
            return ENOMEM;
        }
        cap *= 2;
    }
    grown = realloc(buf->data, cap);
    if (grown == NULL) {
        return ENOMEM;
    }
    buf->data = grown;
    buf->cap = cap;
    return 0;
}

static int buf_append(strbuf *buf, const char *text, size_t len) {
    int rc = buf_reserve(buf, len);

    if (rc != 0) {
        return rc;
    }
    if (len > 0) {
        memcpy(buf->data + buf->len, text, len);
    }
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

static int buf_puts(strbuf *buf, const char *text) {
    return buf_append(buf, text, strlen(text));
}

static char *dup_string(const char *text) {
    size_t len = strlen(text);
    char *copy = malloc(len + 1);

    if (copy != NULL) {
        memcpy(copy, text, len + 1);
    }
    return copy;
}

/* Leading/trailing ASCII whitespace trim; returns a pointer and length. */
static const char *trim(const char *text, size_t len, size_t *out_len) {
    size_t begin = 0;
    size_t end = len;

    while (begin < end && (text[begin] == ' ' || text[begin] == '\t' ||
                           text[begin] == '\r' || text[begin] == '\n')) {
        begin++;
    }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' ||
                           text[end - 1] == '\r' || text[end - 1] == '\n')) {
        end--;
    }
    *out_len = end - begin;
    return text + begin;
}

/* Parse a `[section]` header. Returns 1 when the line is a section header. */
static int parse_section(const char *line, size_t len, char *out,
                         size_t out_cap) {
    size_t trimmed_len;
    const char *trimmed = trim(line, len, &trimmed_len);
    size_t close;

    if (trimmed_len < 2 || trimmed[0] != '[') {
        return 0;
    }
    close = 1;
    while (close < trimmed_len && trimmed[close] != ']') {
        close++;
    }
    if (close >= trimmed_len) {
        return 0;
    }
    {
        size_t name_len;
        const char *name = trim(trimmed + 1, close - 1, &name_len);

        if (name_len + 1 > out_cap) {
            return 0;
        }
        memcpy(out, name, name_len);
        out[name_len] = '\0';
    }
    return 1;
}

static int key_matches(const char *line, size_t len, const char *key) {
    size_t trimmed_len;
    const char *trimmed = trim(line, len, &trimmed_len);
    size_t key_len = strlen(key);
    size_t pos;

    if (trimmed_len < key_len || memcmp(trimmed, key, key_len) != 0) {
        return 0;
    }
    /* Reject a prefix match such as `aws_key_extra`. */
    if (trimmed_len == key_len) {
        return 1;
    }
    pos = key_len;
    return trimmed[pos] == '=' || trimmed[pos] == ':' ||
           trimmed[pos] == ' ' || trimmed[pos] == '\t';
}

static int emit_key_line(strbuf *out, const char *key, const char *secret) {
    int rc = buf_puts(out, key);

    if (rc == 0) {
        rc = buf_puts(out, " = ");
    }
    if (rc == 0) {
        rc = buf_puts(out, secret);
    }
    if (rc == 0) {
        rc = buf_puts(out, "\n");
    }
    return rc;
}

static int contains_line_break(const char *text) {
    return strchr(text, '\n') != NULL || strchr(text, '\r') != NULL;
}

static int read_all(const char *path, char **out, size_t *out_len,
                    int *existed) {
    int fd = open(path, O_RDONLY);
    struct stat st;
    char *data;
    size_t total = 0;
    ssize_t got;

    if (fd < 0) {
        if (errno == ENOENT) {
            *existed = 0;
            *out = dup_string("");
            *out_len = 0;
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
        got = read(fd, data + total, (size_t)st.st_size - total);
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
    *existed = 1;
    *out = data;
    *out_len = total;
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

static int write_backup(const char *path, const char *data, size_t len,
                        char **backup_out) {
    char stamp[32];
    time_t now = time(NULL);
    struct tm tm_utc;
    int attempt;

    if (gmtime_r(&now, &tm_utc) == NULL ||
        strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tm_utc) == 0) {
        return EIO;
    }
    for (attempt = 0; attempt < 100; attempt++) {
        size_t need = strlen(path) + strlen(stamp) + 32;
        char *candidate = malloc(need);
        int fd;
        int rc;
        char *committed;

        if (candidate == NULL) {
            return ENOMEM;
        }
        if (attempt == 0) {
            snprintf(candidate, need, "%s.bak.%s", path, stamp);
        } else {
            snprintf(candidate, need, "%s.bak.%s-%d", path, stamp, attempt);
        }
        fd = open(candidate, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            int open_err = errno;

            free(candidate);
            if (open_err == EEXIST) {
                continue;
            }
            return open_err;
        }
        if (fchmod(fd, 0600) != 0) {
            rc = errno;
            close(fd);
            unlink(candidate);
            free(candidate);
            return rc;
        }
        rc = write_all(fd, data, len);
        if (rc == 0 && fsync(fd) != 0) {
            rc = errno;
        }
        if (close(fd) != 0 && rc == 0) {
            rc = errno;
        }
        if (rc != 0) {
            unlink(candidate);
            free(candidate);
            return rc;
        }
        committed = dup_string(candidate);
        free(candidate);
        if (committed == NULL) {
            return ENOMEM;
        }
        *backup_out = committed;
        return 0;
    }
    return EEXIST;
}

static int atomic_write(const char *path, const char *data, size_t len) {
    char *dircopy = dup_string(path);
    char *slash;
    char *temp;
    size_t need;
    int fd;
    int rc;

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
    need = strlen(dircopy) + sizeof("/.ini.tmp.XXXXXX") + 1;
    temp = malloc(need);
    if (temp == NULL) {
        free(dircopy);
        return ENOMEM;
    }
    snprintf(temp, need, "%s/.ini.tmp.XXXXXX", dircopy);
    fd = mkstemp(temp);
    if (fd < 0) {
        rc = errno;
        free(temp);
        free(dircopy);
        return rc;
    }
    rc = 0;
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

static int build_new_content(const char *input, size_t input_len,
                             const char *section, const char *key,
                             const char *secret, strbuf *out) {
    size_t cursor = 0;
    int target_seen = 0;
    int key_written = 0;
    char current_section[256] = "";
    int rc;

    while (cursor < input_len) {
        size_t start = cursor;
        size_t line_end;
        size_t after;
        char parsed[256];

        while (cursor < input_len && input[cursor] != '\n') {
            cursor++;
        }
        line_end = cursor;
        after = cursor < input_len ? cursor + 1 : cursor;
        cursor = after;

        if (parse_section(input + start, line_end - start, parsed,
                          sizeof parsed)) {
            if (target_seen && !key_written) {
                rc = emit_key_line(out, key, secret);
                if (rc != 0) {
                    return rc;
                }
                key_written = 1;
            }
            if (strcmp(parsed, section) == 0) {
                target_seen = 1;
            }
            rc = buf_append(out, input + start, after - start);
            if (rc != 0) {
                return rc;
            }
            {
                size_t parsed_len = strlen(parsed);

                memcpy(current_section, parsed, parsed_len + 1);
            }
            continue;
        }

        if (target_seen && strcmp(current_section, section) == 0 &&
            key_matches(input + start, line_end - start, key)) {
            if (!key_written) {
                rc = emit_key_line(out, key, secret);
                if (rc != 0) {
                    return rc;
                }
                key_written = 1;
            }
            /* Duplicate occurrences of the same key inside the section are
             * collapsed onto the single freshly written line. */
            continue;
        }

        rc = buf_append(out, input + start, after - start);
        if (rc != 0) {
            return rc;
        }
    }

    if (!target_seen) {
        if (input_len > 0 && input[input_len - 1] != '\n') {
            rc = buf_puts(out, "\n");
            if (rc != 0) {
                return rc;
            }
        }
        if (input_len > 0) {
            rc = buf_puts(out, "\n");
            if (rc != 0) {
                return rc;
            }
        }
        rc = buf_puts(out, "[");
        if (rc == 0) {
            rc = buf_puts(out, section);
        }
        if (rc == 0) {
            rc = buf_puts(out, "]\n");
        }
        if (rc == 0) {
            rc = emit_key_line(out, key, secret);
        }
        return rc;
    }

    if (!key_written) {
        return emit_key_line(out, key, secret);
    }
    return 0;
}

int ini_upsert_section(const char *path, const char *section, const char *key,
                       const char *secret, char **backup_path_out) {
    char *input = NULL;
    size_t input_len = 0;
    int existed = 0;
    strbuf out = {0};
    char *backup = NULL;
    int rc;

    if (backup_path_out != NULL) {
        *backup_path_out = NULL;
    }
    if (path == NULL || section == NULL || key == NULL || secret == NULL ||
        section[0] == '\0' || key[0] == '\0' || contains_line_break(section) ||
        contains_line_break(key) || contains_line_break(secret) ||
        strchr(section, '[') != NULL || strchr(section, ']') != NULL) {
        return EINVAL;
    }

    rc = read_all(path, &input, &input_len, &existed);
    if (rc != 0) {
        return rc;
    }
    rc = build_new_content(input, input_len, section, key, secret, &out);
    if (rc != 0) {
        free(input);
        free(out.data);
        return rc;
    }
    if (existed) {
        rc = write_backup(path, input, input_len, &backup);
        if (rc != 0) {
            free(input);
            free(out.data);
            return rc;
        }
    }
    rc = atomic_write(path, out.data != NULL ? out.data : "", out.len);
    if (rc != 0) {
        free(backup);
        free(input);
        free(out.data);
        return rc;
    }
    if (backup_path_out != NULL) {
        *backup_path_out = backup;
    } else {
        free(backup);
    }
    free(input);
    free(out.data);
    return 0;
}
