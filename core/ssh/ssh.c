/*
 * ssh.c — controlled ssh(1)/scp(1) invocation (spec §4).
 *
 * One argv builder shared by ssh and scp; an exec wrapper that captures stdout
 * for the `STACKCTL_RC=<n>` sentinel, applies the exit-255 reconnect-once rule,
 * enforces a wall-clock timeout, and tears the child down as a process group
 * (SIGTERM, 5 s grace, SIGKILL).
 */

#include "ssh.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SSHC_KILL_GRACE_SEC 5
#define SSHC_POLL_MS 50

static sshc_abort_fn abort_hook;
static void *abort_user;
static sshc_progress_fn progress_hook;
static void *progress_user;
static int progress_interval_sec;

void sshc_set_abort_hook(sshc_abort_fn fn, void *user) {
    abort_hook = fn;
    abort_user = user;
}

void sshc_set_progress_hook(sshc_progress_fn fn, void *user, int interval_sec) {
    progress_hook = fn;
    progress_user = user;
    progress_interval_sec = interval_sec;
}

/* Whole milliseconds between two CLOCK_MONOTONIC readings. */
static long elapsed_millis(const struct timespec *start,
                           const struct timespec *now) {
    return (now->tv_sec - start->tv_sec) * 1000L +
           (now->tv_nsec - start->tv_nsec) / 1000000L;
}

/*
 * Report progress at most once per interval. A non-positive interval is the
 * test seam: it reports on every poll. A positive interval waits for the first
 * tick before reporting so a quick session stays quiet. Runs on the waiting
 * thread, never in a signal handler.
 */
static void maybe_report_progress(const struct timespec *start, long *last_ms) {
    struct timespec now;
    long elapsed;

    if (progress_hook == NULL) {
        return;
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = elapsed_millis(start, &now);
    if (progress_interval_sec > 0) {
        long interval_ms = (long)progress_interval_sec * 1000L;

        if (elapsed < interval_ms) {
            return;
        }
        if (*last_ms >= 0 && elapsed - *last_ms < interval_ms) {
            return;
        }
    }
    *last_ms = elapsed;
    progress_hook(progress_user, (int)(elapsed / 1000));
}

/* ------------------------------------------------------------------------- */
/* argv builder                                                              */
/* ------------------------------------------------------------------------- */

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} argv_builder;

static char *format_alloc(const char *fmt, ...) {
    va_list ap;
    va_list copy;
    int needed;
    char *out;

    va_start(ap, fmt);
    va_copy(copy, ap);
    needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(ap);
        return NULL;
    }
    out = malloc((size_t)needed + 1);
    if (out != NULL) {
        vsnprintf(out, (size_t)needed + 1, fmt, ap);
    }
    va_end(ap);
    return out;
}

static int builder_push_owned(argv_builder *builder, char *owned) {
    if (owned == NULL) {
        return ENOMEM;
    }
    if (builder->count == builder->cap) {
        size_t cap = builder->cap == 0 ? 32 : builder->cap * 2;
        char **grown = realloc(builder->items, cap * sizeof *grown);

        if (grown == NULL) {
            free(owned);
            return ENOMEM;
        }
        builder->items = grown;
        builder->cap = cap;
    }
    builder->items[builder->count++] = owned;
    return 0;
}

static int builder_push(argv_builder *builder, const char *text) {
    size_t len = strlen(text);
    char *copy = malloc(len + 1);

    if (copy != NULL) {
        memcpy(copy, text, len + 1);
    }
    return builder_push_owned(builder, copy);
}

static int builder_push_option(argv_builder *builder, const char *option) {
    int rc = builder_push(builder, "-o");

    if (rc == 0) {
        rc = builder_push(builder, option);
    }
    return rc;
}

static void builder_free(argv_builder *builder) {
    for (size_t i = 0; i < builder->count; i++) {
        free(builder->items[i]);
    }
    free(builder->items);
    builder->items = NULL;
    builder->count = 0;
    builder->cap = 0;
}

static int append_option(argv_builder *builder, const char *name,
                         const char *value) {
    char *joined = format_alloc("%s=%s", name, value);
    int rc;

    if (joined == NULL) {
        return ENOMEM;
    }
    rc = builder_push_option(builder, joined);
    free(joined);
    return rc;
}

static int append_option_int(argv_builder *builder, const char *name, int value) {
    char *joined = format_alloc("%s=%d", name, value);
    int rc;

    if (joined == NULL) {
        return ENOMEM;
    }
    rc = builder_push_option(builder, joined);
    free(joined);
    return rc;
}

static int options_valid(const sshc_options *opts) {
    return opts != NULL && opts->identity != NULL && opts->identity[0] != '\0' &&
           opts->known_hosts != NULL && opts->known_hosts[0] != '\0' &&
           opts->instance_id != NULL && opts->instance_id[0] != '\0' &&
           opts->user != NULL && opts->user[0] != '\0' && opts->port > 0;
}

int sshc_build_argv(sshc_kind kind, const sshc_options *opts,
                    const char *const *operands, size_t operand_count,
                    char ***argv_out) {
    argv_builder builder = {0};
    int alive_interval;
    int alive_count;
    int rc = 0;

    if (argv_out == NULL) {
        return EINVAL;
    }
    *argv_out = NULL;
    if ((kind != SSHC_KIND_SSH && kind != SSHC_KIND_SCP) ||
        !options_valid(opts) || (operand_count > 0 && operands == NULL)) {
        return EINVAL;
    }
    alive_interval =
        opts->server_alive_interval > 0 ? opts->server_alive_interval : 15;
    alive_count =
        opts->server_alive_count_max > 0 ? opts->server_alive_count_max : 3;

    rc = builder_push(&builder, kind == SSHC_KIND_SSH ? "ssh" : "scp");
    if (rc == 0 && kind == SSHC_KIND_SSH) {
        rc = builder_push(&builder, "-T");
    }
    if (rc == 0) {
        rc = builder_push_option(&builder, "BatchMode=yes");
    }
    if (rc == 0) {
        rc = builder_push_option(&builder, "IdentitiesOnly=yes");
    }
    if (rc == 0) {
        rc = builder_push(&builder, "-i");
    }
    if (rc == 0) {
        rc = builder_push(&builder, opts->identity);
    }
    if (rc == 0) {
        rc = builder_push_option(&builder, "UpdateHostKeys=no");
    }
    if (rc == 0) {
        rc = builder_push_option(&builder, "ControlMaster=no");
    }
    if (rc == 0) {
        rc = builder_push_option(&builder, "ControlPath=none");
    }
    if (rc == 0) {
        rc = append_option(&builder, "UserKnownHostsFile", opts->known_hosts);
    }
    if (rc == 0) {
        rc = builder_push_option(&builder, opts->strict_yes
                                                 ? "StrictHostKeyChecking=yes"
                                                 : "StrictHostKeyChecking=accept-new");
    }
    if (rc == 0) {
        rc = append_option(&builder, "HostKeyAlias", opts->instance_id);
    }
    if (rc == 0) {
        rc = append_option_int(&builder, "ServerAliveInterval", alive_interval);
    }
    if (rc == 0) {
        rc = append_option_int(&builder, "ServerAliveCountMax", alive_count);
    }
    if (rc == 0) {
        rc = append_option_int(&builder, "Port", opts->port);
    }
    if (rc == 0) {
        rc = append_option(&builder, "User", opts->user);
    }
    for (size_t i = 0; rc == 0 && i < operand_count; i++) {
        if (operands[i] == NULL) {
            rc = EINVAL;
        } else {
            rc = builder_push(&builder, operands[i]);
        }
    }
    if (rc == 0) {
        char **grown = realloc(builder.items,
                               (builder.count + 1) * sizeof *builder.items);

        if (grown == NULL) {
            rc = ENOMEM;
        } else {
            builder.items = grown;
            builder.items[builder.count] = NULL;
            *argv_out = builder.items;
            builder.items = NULL;
            builder.count = 0;
        }
    }
    builder_free(&builder);
    return rc;
}

void sshc_argv_free(char **argv) {
    if (argv == NULL) {
        return;
    }
    for (size_t i = 0; argv[i] != NULL; i++) {
        free(argv[i]);
    }
    free(argv);
}

/* ------------------------------------------------------------------------- */
/* Exec                                                                      */
/* ------------------------------------------------------------------------- */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} capture;

static void capture_free(capture *cap) {
    free(cap->data);
    cap->data = NULL;
    cap->len = 0;
    cap->cap = 0;
}

static int capture_append(capture *cap, const char *data, size_t len) {
    if (cap->len + len + 1 > cap->cap) {
        size_t want = cap->len + len + 1;
        size_t next = cap->cap == 0 ? 1024 : cap->cap;

        while (next < want) {
            if (next > ((size_t)-1) / 2) {
                return ENOMEM;
            }
            next *= 2;
        }
        char *grown = realloc(cap->data, next);

        if (grown == NULL) {
            return ENOMEM;
        }
        cap->data = grown;
        cap->cap = next;
    }
    memcpy(cap->data + cap->len, data, len);
    cap->len += len;
    cap->data[cap->len] = '\0';
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Sentinel parsing                                                          */
/* ------------------------------------------------------------------------- */

static int is_space_char(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int parse_prefixed(const capture *out, const char *prefix, int *value) {
    size_t end = out->len;
    size_t start;
    size_t prefix_len = strlen(prefix);
    size_t pos;
    long parsed = 0;
    int digits = 0;

    while (end > 0 && is_space_char(out->data[end - 1])) {
        end--;
    }
    start = end;
    while (start > 0 && out->data[start - 1] != '\n') {
        start--;
    }
    if (end - start < prefix_len ||
        memcmp(out->data + start, prefix, prefix_len) != 0) {
        return 0;
    }
    pos = start + prefix_len;
    while (pos < end && out->data[pos] >= '0' && out->data[pos] <= '9') {
        if (parsed > 214748363L) {
            return 0;
        }
        parsed = parsed * 10 + (out->data[pos] - '0');
        digits++;
        pos++;
    }
    if (!digits || pos != end) {
        return 0;
    }
    *value = (int)parsed;
    return 1;
}

static int parse_decimal(const capture *out, int *value) {
    size_t begin = 0;
    size_t end = out->len;
    long parsed = 0;
    int digits = 0;

    while (begin < end && is_space_char(out->data[begin])) {
        begin++;
    }
    while (end > begin && is_space_char(out->data[end - 1])) {
        end--;
    }
    if (begin == end) {
        return 0;
    }
    for (size_t i = begin; i < end; i++) {
        if (out->data[i] < '0' || out->data[i] > '9') {
            return 0;
        }
        if (parsed > 214748363L) {
            return 0;
        }
        parsed = parsed * 10 + (out->data[i] - '0');
        digits++;
    }
    if (!digits) {
        return 0;
    }
    *value = (int)parsed;
    return 1;
}

/* ------------------------------------------------------------------------- */
/* Exec core                                                                 */
/* ------------------------------------------------------------------------- */

static int drain_pipe(int fd, capture *out) {
    char chunk[4096];

    for (;;) {
        ssize_t got = read(fd, chunk, sizeof chunk);

        if (got > 0) {
            int rc = capture_append(out, chunk, (size_t)got);

            if (rc != 0) {
                return rc;
            }
            continue;
        }
        if (got == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return errno;
    }
}

static void terminate_group(pid_t pid, int *status) {
    struct timespec grace_start;
    int reaped = 0;

    (void)kill(-pid, SIGTERM);
    clock_gettime(CLOCK_MONOTONIC, &grace_start);
    while (!reaped) {
        pid_t waited = waitpid(pid, status, WNOHANG);
        struct timespec now;

        if (waited == pid) {
            reaped = 1;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            reaped = 1;
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - grace_start.tv_sec >= SSHC_KILL_GRACE_SEC) {
            (void)kill(-pid, SIGKILL);
            while (waitpid(pid, status, 0) < 0 && errno == EINTR) {
            }
            reaped = 1;
            break;
        }
        {
            struct timespec pause = {0, SSHC_POLL_MS * 1000 * 1000};

            nanosleep(&pause, NULL);
        }
    }
}

static int run_once(char *const argv[], int timeout_sec, capture *out,
                    int *status_out, int *timed_out) {
    int pipe_fds[2];
    pid_t child;
    struct timespec start;
    long last_progress_ms = -1;
    int status = 0;
    int finished = 0;
    int aborted = 0;

    *timed_out = 0;
    *status_out = 0;
    if (pipe(pipe_fds) != 0) {
        return errno;
    }
    child = fork();
    if (child < 0) {
        int rc = errno;

        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return rc;
    }
    if (child == 0) {
        (void)setpgid(0, 0);
        close(pipe_fds[0]);
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(pipe_fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipe_fds[1]);
    {
        int flags = fcntl(pipe_fds[0], F_GETFL, 0);

        if (flags >= 0) {
            (void)fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!finished) {
        struct pollfd pfd;
        pid_t waited;
        struct timespec now;

        (void)drain_pipe(pipe_fds[0], out);
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            finished = 1;
            break;
        }
        maybe_report_progress(&start, &last_progress_ms);
        if (waited < 0 && errno != EINTR) {
            finished = 1;
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (timeout_sec > 0 &&
            now.tv_sec - start.tv_sec >= timeout_sec) {
            terminate_group(child, &status);
            *timed_out = 1;
            finished = 1;
            break;
        }
        if (abort_hook != NULL && abort_hook(abort_user) != 0) {
            terminate_group(child, &status);
            aborted = 1;
            finished = 1;
            break;
        }
        pfd.fd = pipe_fds[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        (void)poll(&pfd, 1, SSHC_POLL_MS);
    }
    if (aborted) {
        close(pipe_fds[0]);
        *status_out = status;
        return EINTR;
    }
    if (!*timed_out) {
        int flags;

        /* Child is gone; unblock and collect whatever remains in the pipe. */
        flags = fcntl(pipe_fds[0], F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(pipe_fds[0], F_SETFL, flags & ~O_NONBLOCK);
        }
        (void)drain_pipe(pipe_fds[0], out);
    }
    close(pipe_fds[0]);
    *status_out = status;
    return 0;
}

int sshc_exec(char *const argv[], int timeout_sec,
              const sshc_sentinel_spec *sentinel, int *remote_rc) {
    capture out = {0};
    int status = 0;
    int timed_out = 0;
    int rc;
    int exit_code;

    if (argv == NULL || argv[0] == NULL || remote_rc == NULL) {
        return EINVAL;
    }
    rc = run_once(argv, timeout_sec, &out, &status, &timed_out);
    if (rc != 0) {
        capture_free(&out);
        return rc;
    }
    if (timed_out) {
        capture_free(&out);
        return ETIMEDOUT;
    }
    if (sentinel != NULL && sentinel->prefix != NULL &&
        sentinel->prefix[0] != '\0') {
        int value = 0;

        if (parse_prefixed(&out, sentinel->prefix, &value)) {
            *remote_rc = value;
            capture_free(&out);
            return 0;
        }
    }
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    } else {
        exit_code = 1;
    }
    if (exit_code == 255) {
        if (sentinel != NULL && sentinel->reconnect_argv != NULL &&
            sentinel->reconnect_argv[0] != NULL) {
            capture reconnect = {0};
            int reconnect_status = 0;
            int reconnect_timed_out = 0;
            int value = 0;

            rc = run_once(sentinel->reconnect_argv, timeout_sec, &reconnect,
                          &reconnect_status, &reconnect_timed_out);
            if (rc == 0 && !reconnect_timed_out &&
                parse_decimal(&reconnect, &value)) {
                *remote_rc = value;
                capture_free(&reconnect);
                capture_free(&out);
                return 0;
            }
            capture_free(&reconnect);
            if (rc != 0) {
                capture_free(&out);
                return rc;
            }
            capture_free(&out);
            return ENOTCONN;
        }
        capture_free(&out);
        return ENOTCONN;
    }
    *remote_rc = exit_code;
    capture_free(&out);
    return 0;
}
