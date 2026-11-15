/*
 * state.c — stackctl on-disk state (spec §2 state module, §8 binding map).
 *
 * XDG namespace + 0700 directories, process-global flock, FQDN→instance binding
 * map with the spec §8 replace-vs-hard-error policy, append-only 0600 launch /
 * release / operations records, and secret redaction for the audit trail.
 */

#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define STATE_TIMESTAMP_MAX 32

struct state_store {
    char *base;
    char *root;
    char *dir;
    char *project;
    char *region;
    char *known_hosts;
    char *bindings;
    char *operations;
    char *launch_records;
    char *release_history;
    char *lock_path;
};

/* Process-global exclusive lock (CONTRACT permits the state module's store). */
static int g_lock_fd = -1;

/* ------------------------------------------------------------------------- */
/* Small allocation + string helpers                                         */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} strbuf;

static char *dup_string(const char *text) {
    size_t len = strlen(text);
    char *copy = malloc(len + 1);

    if (copy != NULL) {
        memcpy(copy, text, len + 1);
    }
    return copy;
}

static char *concat2(const char *a, const char *b) {
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    char *out = malloc(alen + blen + 1);

    if (out != NULL) {
        memcpy(out, a, alen);
        memcpy(out + alen, b, blen + 1);
    }
    return out;
}

static char *concat3(const char *a, const char *b, const char *c) {
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    size_t clen = strlen(c);
    char *out = malloc(alen + blen + clen + 1);

    if (out != NULL) {
        memcpy(out, a, alen);
        memcpy(out + alen, b, blen);
        memcpy(out + alen + blen, c, clen + 1);
    }
    return out;
}

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

static void buf_free(strbuf *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

static int has_bad_name_char(const char *text) {
    return strchr(text, '/') != NULL || strchr(text, '\\') != NULL ||
           strchr(text, '\n') != NULL || strchr(text, '\t') != NULL;
}

static int field_copy(char *dst, size_t cap, const char *src) {
    size_t len = strlen(src);

    if (len + 1 > cap) {
        return ENAMETOOLONG;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Filesystem primitives                                                     */
/* ------------------------------------------------------------------------- */

static int mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t len = strlen(path);
    size_t i;

    if (len == 0 || len >= sizeof buffer) {
        return ENAMETOOLONG;
    }
    memcpy(buffer, path, len + 1);
    for (i = 1; i < len; i++) {
        if (buffer[i] == '/') {
            buffer[i] = '\0';
            if (mkdir(buffer, 0700) != 0 && errno != EEXIST) {
                return errno;
            }
            buffer[i] = '/';
        }
    }
    if (mkdir(buffer, 0700) != 0 && errno != EEXIST) {
        return errno;
    }
    if (chmod(buffer, 0700) != 0) {
        return errno;
    }
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

static int read_all(const char *path, char **out, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    struct stat st;
    char *data;
    size_t total = 0;

    if (fd < 0) {
        if (errno == ENOENT) {
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
    *out_len = total;
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
    need = strlen(dircopy) + sizeof("/.state.tmp.XXXXXX") + 1;
    temp = malloc(need);
    if (temp == NULL) {
        free(dircopy);
        return ENOMEM;
    }
    snprintf(temp, need, "%s/.state.tmp.XXXXXX", dircopy);
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

static int append_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    int rc;

    if (fd < 0) {
        return errno;
    }
    if (fchmod(fd, 0600) != 0) {
        rc = errno;
        close(fd);
        return rc;
    }
    rc = write_all(fd, text, strlen(text));
    if (close(fd) != 0 && rc == 0) {
        rc = errno;
    }
    return rc;
}

static void timestamp_utc(char out[STATE_TIMESTAMP_MAX]) {
    time_t now = time(NULL);
    struct tm tm_utc;

    if (gmtime_r(&now, &tm_utc) == NULL ||
        strftime(out, STATE_TIMESTAMP_MAX, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        snprintf(out, STATE_TIMESTAMP_MAX, "1970-01-01T00:00:00Z");
    }
}

/* ------------------------------------------------------------------------- */
/* Namespace resolution                                                      */
/* ------------------------------------------------------------------------- */

static char *resolve_base(void) {
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home;

    if (xdg != NULL && xdg[0] != '\0') {
        return dup_string(xdg);
    }
    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return NULL;
    }
    return concat2(home, "/.local/state");
}

static int valid_component(const char *text) {
    return text != NULL && text[0] != '\0' && !has_bad_name_char(text) &&
           strcmp(text, ".") != 0 && strcmp(text, "..") != 0;
}

int state_open(const char *project, const char *region, state_store **out) {
    state_store *store;
    char *base;
    char *namespace;
    char *root;
    int rc;

    if (out == NULL) {
        return EINVAL;
    }
    *out = NULL;
    if (!valid_component(project) || !valid_component(region)) {
        return EINVAL;
    }
    base = resolve_base();
    if (base == NULL) {
        return ENOENT;
    }
    root = concat2(base, "/stackctl");
    namespace = concat3(project, ".", region);
    if (root == NULL || namespace == NULL) {
        free(base);
        free(root);
        free(namespace);
        return ENOMEM;
    }
    store = calloc(1, sizeof *store);
    if (store == NULL) {
        free(base);
        free(root);
        free(namespace);
        return ENOMEM;
    }
    store->base = base;
    store->root = root;
    store->project = dup_string(project);
    store->region = dup_string(region);
    store->dir = concat3(root, "/", namespace);
    store->lock_path = store->dir == NULL ? NULL : concat2(store->dir, ".lock");
    free(namespace);
    if (store->project == NULL || store->region == NULL || store->dir == NULL ||
        store->lock_path == NULL) {
        state_close(store);
        return ENOMEM;
    }
    rc = mkdir_p(root);
    if (rc == 0) {
        rc = mkdir_p(store->dir);
    }
    if (rc != 0) {
        state_close(store);
        return rc;
    }
    store->known_hosts = concat2(store->dir, "/known_hosts");
    store->bindings = concat2(store->dir, "/bindings");
    store->operations = concat2(store->dir, "/operations.log");
    store->launch_records = concat2(store->dir, "/launch-records.log");
    store->release_history = concat2(store->dir, "/release-history.log");
    if (store->known_hosts == NULL || store->bindings == NULL ||
        store->operations == NULL || store->launch_records == NULL ||
        store->release_history == NULL) {
        state_close(store);
        return ENOMEM;
    }
    *out = store;
    return 0;
}

void state_close(state_store *store) {
    if (store == NULL) {
        return;
    }
    free(store->base);
    free(store->root);
    free(store->dir);
    free(store->project);
    free(store->region);
    free(store->known_hosts);
    free(store->bindings);
    free(store->operations);
    free(store->launch_records);
    free(store->release_history);
    free(store->lock_path);
    free(store);
}

const char *state_dir(const state_store *store) { return store->dir; }
const char *state_known_hosts_path(const state_store *store) {
    return store->known_hosts;
}
const char *state_bindings_path(const state_store *store) {
    return store->bindings;
}
const char *state_operations_log_path(const state_store *store) {
    return store->operations;
}
const char *state_launch_records_path(const state_store *store) {
    return store->launch_records;
}
const char *state_release_history_path(const state_store *store) {
    return store->release_history;
}
const char *state_lock_path(const state_store *store) {
    return store->lock_path;
}
const char *state_project(const state_store *store) { return store->project; }
const char *state_region(const state_store *store) { return store->region; }

/* ------------------------------------------------------------------------- */
/* Locking                                                                   */
/* ------------------------------------------------------------------------- */

int state_lock(const char *project, const char *region, int timeout_sec) {
    char *base;
    char *root;
    char *namespace;
    char *path;
    int fd;
    int rc;

    if (!valid_component(project) || !valid_component(region)) {
        return EINVAL;
    }
    base = resolve_base();
    if (base == NULL) {
        return ENOENT;
    }
    root = concat2(base, "/stackctl");
    namespace = concat3(project, ".", region);
    if (root == NULL || namespace == NULL) {
        free(base);
        free(root);
        free(namespace);
        return ENOMEM;
    }
    path = concat3(root, "/", namespace);
    if (path == NULL) {
        free(base);
        free(root);
        free(namespace);
        return ENOMEM;
    }
    {
        char *lock_path = concat2(path, ".lock");

        free(path);
        if (lock_path == NULL) {
            free(base);
            free(root);
            free(namespace);
            return ENOMEM;
        }
        path = lock_path;
    }
    free(namespace);
    rc = mkdir_p(root);
    free(root);
    free(base);
    if (rc != 0) {
        free(path);
        return rc;
    }
    fd = open(path, O_RDWR | O_CREAT, 0600);
    free(path);
    if (fd < 0) {
        return errno;
    }
    if (fchmod(fd, 0600) != 0) {
        rc = errno;
        close(fd);
        return rc;
    }
    if (timeout_sec < 0) {
        do {
            rc = flock(fd, LOCK_EX);
        } while (rc != 0 && errno == EINTR);
        if (rc != 0) {
            rc = errno;
            close(fd);
            return rc;
        }
    } else {
        struct timespec start;
        int last_error = ETIMEDOUT;

        clock_gettime(CLOCK_MONOTONIC, &start);
        for (;;) {
            struct timespec now;

            rc = flock(fd, LOCK_EX | LOCK_NB);
            if (rc == 0) {
                break;
            }
            if (errno != EWOULDBLOCK && errno != EINTR) {
                last_error = errno;
                break;
            }
            if (timeout_sec == 0) {
                last_error = ETIMEDOUT;
                break;
            }
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - start.tv_sec >= timeout_sec) {
                last_error = ETIMEDOUT;
                break;
            }
            {
                struct timespec pause = {0, 50 * 1000 * 1000};

                nanosleep(&pause, NULL);
            }
        }
        if (rc != 0) {
            close(fd);
            return last_error;
        }
    }
    if (g_lock_fd >= 0) {
        close(g_lock_fd);
    }
    g_lock_fd = fd;
    return 0;
}

int state_unlock(void) {
    int fd = g_lock_fd;

    if (fd < 0) {
        return EBADF;
    }
    g_lock_fd = -1;
    (void)flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Binding map                                                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    kh_binding *items;
    size_t count;
    size_t cap;
} binding_list;

static void binding_list_free(binding_list *list) {
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int binding_list_push(binding_list *list, const kh_binding *binding) {
    if (list->count == list->cap) {
        size_t cap = list->cap == 0 ? 8 : list->cap * 2;
        kh_binding *grown = realloc(list->items, cap * sizeof *grown);

        if (grown == NULL) {
            return ENOMEM;
        }
        list->items = grown;
        list->cap = cap;
    }
    list->items[list->count++] = *binding;
    return 0;
}

static int parse_binding_line(char *line, kh_binding *out) {
    char *fields[4];
    size_t count = 0;
    char *cursor = line;

    while (count < 4) {
        char *tab = strchr(cursor, '\t');

        fields[count++] = cursor;
        if (tab == NULL) {
            break;
        }
        *tab = '\0';
        cursor = tab + 1;
    }
    if (count != 4 || strchr(fields[3], '\t') != NULL ||
        fields[0][0] == '\0' || fields[1][0] == '\0' || fields[2][0] == '\0' ||
        fields[3][0] == '\0') {
        return EINVAL;
    }
    if (field_copy(out->instance_id, sizeof out->instance_id, fields[0]) != 0 ||
        field_copy(out->host_key, sizeof out->host_key, fields[1]) != 0 ||
        field_copy(out->fqdn, sizeof out->fqdn, fields[2]) != 0 ||
        field_copy(out->ip, sizeof out->ip, fields[3]) != 0) {
        return ENAMETOOLONG;
    }
    return 0;
}

static int read_bindings(const state_store *store, binding_list *list) {
    char *data = NULL;
    size_t len = 0;
    char *cursor;
    int rc = read_all(store->bindings, &data, &len);

    if (rc != 0) {
        return rc;
    }
    cursor = data;
    while (*cursor != '\0') {
        char *newline = strchr(cursor, '\n');
        kh_binding binding;

        if (newline != NULL) {
            *newline = '\0';
        }
        if (*cursor != '\0') {
            memset(&binding, 0, sizeof binding);
            rc = parse_binding_line(cursor, &binding);
            if (rc != 0) {
                free(data);
                binding_list_free(list);
                return rc;
            }
            rc = binding_list_push(list, &binding);
            if (rc != 0) {
                free(data);
                binding_list_free(list);
                return rc;
            }
        }
        if (newline == NULL) {
            break;
        }
        cursor = newline + 1;
    }
    free(data);
    (void)len;
    return 0;
}

static int write_bindings(const state_store *store, const binding_list *list) {
    strbuf out = {0};
    int rc = 0;

    for (size_t i = 0; i < list->count && rc == 0; i++) {
        const kh_binding *binding = &list->items[i];

        rc = buf_puts(&out, binding->instance_id);
        if (rc == 0) {
            rc = buf_puts(&out, "\t");
        }
        if (rc == 0) {
            rc = buf_puts(&out, binding->host_key);
        }
        if (rc == 0) {
            rc = buf_puts(&out, "\t");
        }
        if (rc == 0) {
            rc = buf_puts(&out, binding->fqdn);
        }
        if (rc == 0) {
            rc = buf_puts(&out, "\t");
        }
        if (rc == 0) {
            rc = buf_puts(&out, binding->ip);
        }
        if (rc == 0) {
            rc = buf_puts(&out, "\n");
        }
    }
    if (rc == 0) {
        rc = atomic_write(store->bindings, out.data != NULL ? out.data : "",
                          out.len);
    }
    buf_free(&out);
    return rc;
}

static int validate_binding(const kh_binding *binding) {
    if (binding == NULL) {
        return EINVAL;
    }
    return binding->instance_id[0] == '\0' || binding->host_key[0] == '\0' ||
                   binding->fqdn[0] == '\0' || binding->ip[0] == '\0' ||
                   has_bad_name_char(binding->instance_id) ||
                   has_bad_name_char(binding->host_key) ||
                   has_bad_name_char(binding->fqdn) ||
                   has_bad_name_char(binding->ip)
               ? EINVAL
               : 0;
}

int state_binding_get(state_store *store, const char *instance_id,
                      kh_binding *out) {
    binding_list list = {0};
    int rc;

    if (store == NULL || instance_id == NULL || out == NULL) {
        return EINVAL;
    }
    rc = read_bindings(store, &list);
    if (rc != 0) {
        return rc;
    }
    rc = ENOENT;
    for (size_t i = 0; i < list.count; i++) {
        if (strcmp(list.items[i].instance_id, instance_id) == 0) {
            *out = list.items[i];
            rc = 0;
            break;
        }
    }
    binding_list_free(&list);
    return rc;
}

static int binding_apply(state_store *store, const kh_binding *binding,
                         int force) {
    binding_list current = {0};
    binding_list next = {0};
    int rc;
    int warn_replaced = 0;

    rc = validate_binding(binding);
    if (rc != 0) {
        return rc;
    }
    rc = read_bindings(store, &current);
    if (rc != 0) {
        return rc;
    }
    if (!force) {
        for (size_t i = 0; i < current.count; i++) {
            if (strcmp(current.items[i].instance_id, binding->instance_id) == 0 &&
                strcmp(current.items[i].host_key, binding->host_key) != 0) {
                binding_list_free(&current);
                return EPERM; /* same instance-id, changed host key: hard error */
            }
        }
    }
    for (size_t i = 0; i < current.count; i++) {
        const kh_binding *existing = &current.items[i];

        if (strcmp(existing->instance_id, binding->instance_id) == 0) {
            continue;
        }
        if (strcmp(existing->fqdn, binding->fqdn) == 0) {
            if (strcmp(existing->host_key, binding->host_key) != 0) {
                warn_replaced = 1;
            }
            continue; /* new instance-id claims the FQDN: replace */
        }
        rc = binding_list_push(&next, existing);
        if (rc != 0) {
            binding_list_free(&current);
            binding_list_free(&next);
            return rc;
        }
    }
    rc = binding_list_push(&next, binding);
    if (rc == 0) {
        rc = write_bindings(store, &next);
    }
    if (rc == 0 && warn_replaced) {
        fprintf(stderr,
                "stackctl: state: replacing host-key binding for FQDN %s with "
                "instance %s\n",
                binding->fqdn, binding->instance_id);
    }
    binding_list_free(&current);
    binding_list_free(&next);
    return rc;
}

int state_binding_put(state_store *store, const kh_binding *binding) {
    return binding_apply(store, binding, 0);
}

int state_binding_replace(state_store *store, const kh_binding *binding) {
    return binding_apply(store, binding, 1);
}

int state_binding_forget(state_store *store, const char *instance_id) {
    binding_list current = {0};
    binding_list next = {0};
    int rc;

    if (store == NULL || instance_id == NULL || instance_id[0] == '\0') {
        return EINVAL;
    }
    rc = read_bindings(store, &current);
    if (rc != 0) {
        return rc;
    }
    for (size_t i = 0; i < current.count; i++) {
        if (strcmp(current.items[i].instance_id, instance_id) == 0) {
            continue;
        }
        rc = binding_list_push(&next, &current.items[i]);
        if (rc != 0) {
            binding_list_free(&current);
            binding_list_free(&next);
            return rc;
        }
    }
    rc = write_bindings(store, &next);
    binding_list_free(&current);
    binding_list_free(&next);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Append-only records                                                       */
/* ------------------------------------------------------------------------- */

int state_launch_record_append(state_store *store,
                               const state_launch_record *record) {
    char stamp[STATE_TIMESTAMP_MAX];
    strbuf line = {0};
    int rc;

    if (store == NULL || record == NULL || record->instance_id[0] == '\0' ||
        has_bad_name_char(record->instance_id) ||
        has_bad_name_char(record->nonce) || has_bad_name_char(record->fqdn) ||
        has_bad_name_char(record->ip) || has_bad_name_char(record->replaced)) {
        return EINVAL;
    }
    timestamp_utc(stamp);
    rc = buf_puts(&line, stamp);
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, record->instance_id);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, record->nonce);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, record->fqdn);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, record->ip);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, record->replaced);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\n");
    }
    if (rc == 0) {
        rc = append_file(store->launch_records, line.data);
    }
    buf_free(&line);
    return rc;
}

int state_release_history_append(state_store *store, const char *tag) {
    char stamp[STATE_TIMESTAMP_MAX];
    strbuf line = {0};
    int rc;

    if (store == NULL || tag == NULL || tag[0] == '\0' || has_bad_name_char(tag)) {
        return EINVAL;
    }
    timestamp_utc(stamp);
    rc = buf_puts(&line, stamp);
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, tag);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\n");
    }
    if (rc == 0) {
        rc = append_file(store->release_history, line.data);
    }
    buf_free(&line);
    return rc;
}

/* Case-insensitive substring test over ASCII. */
static int contains_ci(const char *haystack, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);

    if (needle_len == 0 || hay_len < needle_len) {
        return 0;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        size_t j = 0;

        while (j < needle_len) {
            char a = haystack[i + j];
            char b = needle[j];

            if (a >= 'A' && a <= 'Z') {
                a = (char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char)(b - 'A' + 'a');
            }
            if (a != b) {
                break;
            }
            j++;
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int sensitive_key(const char *key, size_t key_len) {
    return contains_ci(key, key_len, "password") ||
           contains_ci(key, key_len, "secret") ||
           contains_ci(key, key_len, "token");
}

static int redact_args(const char *args, strbuf *out) {
    const char *cursor = args;
    int redact_next = 0;
    int first = 1;
    int rc = 0;

    while (*cursor != '\0' && rc == 0) {
        const char *start;
        const char *end;

        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') {
            cursor++;
        }
        end = cursor;

        if (!first) {
            rc = buf_puts(out, " ");
        }
        if (rc != 0) {
            break;
        }
        first = 0;

        if (redact_next) {
            rc = buf_puts(out, "<redacted>");
            redact_next = 0;
        } else {
            const char *equals = memchr(start, '=', (size_t)(end - start));

            if (equals != NULL &&
                sensitive_key(start, (size_t)(equals - start))) {
                rc = buf_append(out, start, (size_t)(equals - start) + 1);
                if (rc == 0) {
                    rc = buf_puts(out, "<redacted>");
                }
            } else if ((size_t)(end - start) == 10 &&
                       memcmp(start, "--password", 10) == 0) {
                rc = buf_puts(out, "--password");
                redact_next = 1;
            } else {
                rc = buf_append(out, start, (size_t)(end - start));
            }
        }
    }
    return rc;
}

int state_operations_log_append(state_store *store, const char *verb,
                                const char *args, const char *outcome) {
    char stamp[STATE_TIMESTAMP_MAX];
    strbuf redacted = {0};
    strbuf line = {0};
    int rc;

    if (store == NULL || verb == NULL || outcome == NULL || verb[0] == '\0' ||
        has_bad_name_char(verb)) {
        return EINVAL;
    }
    if (args == NULL) {
        args = "";
    }
    rc = redact_args(args, &redacted);
    if (rc != 0) {
        buf_free(&redacted);
        return rc;
    }
    timestamp_utc(stamp);
    rc = buf_puts(&line, stamp);
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, verb);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, redacted.data != NULL ? redacted.data : "");
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\t");
    }
    if (rc == 0) {
        rc = buf_puts(&line, outcome);
    }
    if (rc == 0) {
        rc = buf_puts(&line, "\n");
    }
    if (rc == 0) {
        rc = append_file(store->operations, line.data);
    }
    buf_free(&redacted);
    buf_free(&line);
    return rc;
}
