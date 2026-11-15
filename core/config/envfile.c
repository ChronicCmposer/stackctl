/*
 * envfile.c — flat KEY=VALUE parser (spec §3); see envfile.h.
 *
 * Deliberately no interpolation: a value is taken literally after optional
 * trimming and quote removal, so `$FOO` stays `$FOO`.
 */

#include "envfile.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENVFILE_LINE_MAX 4096
#define ENVFILE_KEY_MAX 256

typedef struct {
    char *key;
    char *value;
} envfile_entry;

struct config_envfile {
    envfile_entry *items;
    size_t len;
    size_t cap;
};

static int is_key_start(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int is_key_char(char c) {
    return is_key_start(c) || (c >= '0' && c <= '9');
}

static int key_is_valid(const char *key) {
    if (key[0] == '\0' || !is_key_start(key[0])) {
        return 0;
    }
    for (const char *p = key + 1; *p != '\0'; p++) {
        if (!is_key_char(*p)) {
            return 0;
        }
    }
    return 1;
}

static const char *find_value(const config_envfile *ef, const char *key) {
    for (size_t i = 0; i < ef->len; i++) {
        if (strcmp(ef->items[i].key, key) == 0) {
            return ef->items[i].value;
        }
    }
    return NULL;
}

static int append_entry(config_envfile *ef, const char *key, const char *value) {
    if (ef->len == ef->cap) {
        size_t next_cap = ef->cap == 0 ? 16 : ef->cap * 2;
        envfile_entry *grown = realloc(ef->items, next_cap * sizeof *grown);
        if (grown == NULL) {
            return -1;
        }
        ef->items = grown;
        ef->cap = next_cap;
    }
    ef->items[ef->len].key = strdup(key);
    ef->items[ef->len].value = strdup(value);
    if (ef->items[ef->len].key == NULL || ef->items[ef->len].value == NULL) {
        free(ef->items[ef->len].key);
        free(ef->items[ef->len].value);
        return -1;
    }
    ef->len++;
    return 0;
}

/* Trim leading spaces/tabs in place. */
static char *skip_leading_space(char *p) {
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/*
 * Split one logical line into key and value. Returns 0 on success, -1 on a
 * malformed line. The line buffer is mutated (NUL terminators inserted).
 */
static int parse_line(char *line, char **key_out, char **value_out) {
    char *p = skip_leading_space(line);
    char *eq;
    size_t value_len;

    if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#') {
        return 1; /* blank or comment: not an entry */
    }
    if (strncmp(p, "export ", 7) == 0) {
        p = skip_leading_space(p + 7);
    }

    eq = strchr(p, '=');
    if (eq == NULL) {
        return -1;
    }
    *eq = '\0';

    /* Trim trailing whitespace from the name. */
    {
        char *end = p + strlen(p);
        while (end > p && (end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }
    }
    if (!key_is_valid(p)) {
        return -1;
    }

    /* Trim the line ending, then strip one pair of surrounding quotes. */
    {
        char *value = eq + 1;
        value_len = strlen(value);
        while (value_len > 0 &&
               (value[value_len - 1] == '\n' || value[value_len - 1] == '\r')) {
            value[--value_len] = '\0';
        }
        if (value_len >= 2 &&
            ((value[0] == '"' && value[value_len - 1] == '"') ||
             (value[0] == '\'' && value[value_len - 1] == '\''))) {
            value[value_len - 1] = '\0';
            value++;
        }
        *key_out = p;
        *value_out = value;
    }
    return 0;
}

int config_envfile_load(const char *path, config_envfile **out, char *err, size_t err_cap) {
    FILE *file;
    config_envfile *ef;
    char line[ENVFILE_LINE_MAX];
    size_t line_no = 0;

    if (out == NULL) {
        return -1;
    }
    *out = NULL;
    if (err != NULL && err_cap > 0) {
        err[0] = '\0';
    }
    if (path == NULL) {
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "envfile path is null");
        }
        return -1;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "could not open %s: %s", path,
                     strerror(errno));
        }
        return -1;
    }

    ef = calloc(1, sizeof *ef);
    if (ef == NULL) {
        fclose(file);
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "out of memory reading %s", path);
        }
        return -1;
    }

    while (fgets(line, sizeof line, file) != NULL) {
        char *key = NULL;
        char *value = NULL;
        int parsed;

        line_no++;
        /* A full buffer without a newline means the logical line overflowed. */
        if (strlen(line) == sizeof line - 1 && line[sizeof line - 2] != '\n' &&
            !feof(file)) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "%s:%zu: line too long", path, line_no);
            }
            goto fail;
        }

        parsed = parse_line(line, &key, &value);
        if (parsed < 0) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "%s:%zu: malformed KEY=VALUE line", path,
                         line_no);
            }
            goto fail;
        }
        if (parsed == 1) {
            continue;
        }
        if (strlen(key) >= ENVFILE_KEY_MAX) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "%s:%zu: key too long", path, line_no);
            }
            goto fail;
        }
        if (find_value(ef, key) != NULL) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "%s:%zu: duplicate key %s", path,
                         line_no, key);
            }
            goto fail;
        }
        if (append_entry(ef, key, value) != 0) {
            if (err != NULL && err_cap > 0) {
                snprintf(err, err_cap, "out of memory reading %s", path);
            }
            goto fail;
        }
    }

    if (ferror(file)) {
        if (err != NULL && err_cap > 0) {
            snprintf(err, err_cap, "could not read %s: %s", path,
                     strerror(errno));
        }
        goto fail;
    }

    fclose(file);
    *out = ef;
    return 0;

fail:
    fclose(file);
    config_envfile_free(ef);
    return -1;
}

const char *config_envfile_get(const config_envfile *ef, const char *key) {
    if (ef == NULL || key == NULL) {
        return NULL;
    }
    return find_value(ef, key);
}

size_t config_envfile_count(const config_envfile *ef) {
    return ef == NULL ? 0 : ef->len;
}

const char *config_envfile_key_at(const config_envfile *ef, size_t index) {
    if (ef == NULL || index >= ef->len) {
        return NULL;
    }
    return ef->items[index].key;
}

const char *config_envfile_value_at(const config_envfile *ef, size_t index) {
    if (ef == NULL || index >= ef->len) {
        return NULL;
    }
    return ef->items[index].value;
}

void config_envfile_free(config_envfile *ef) {
    if (ef == NULL) {
        return;
    }
    for (size_t i = 0; i < ef->len; i++) {
        free(ef->items[i].key);
        free(ef->items[i].value);
    }
    free(ef->items);
    free(ef);
}
