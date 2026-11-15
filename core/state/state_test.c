/*
 * state_test.c — unit tests for core/state (spec §2, §8).
 *
 * Covers XDG/HOME resolution + 0700 directory, lock timeout, binding
 * replace-vs-hard-error matrix, append-only 0600 logs, secret redaction and
 * launch/release records. No external test framework: exit non-zero on any
 * failed check.
 */

#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static char *make_temp_root(void) {
    char template[] = "/tmp/stackctl-state-XXXXXX";
    char *root = mkdtemp(template);

    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    return strdup(root);
}

static char *read_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    char *buffer;
    long size;

    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buffer = malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
        free(buffer);
        fclose(fp);
        return NULL;
    }
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

static int file_mode(const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        return -1;
    }
    return (int)(st.st_mode & 0777);
}

static size_t count_lines(const char *text) {
    size_t lines = 0;

    for (const char *cursor = text; *cursor != '\0'; cursor++) {
        if (*cursor == '\n') {
            lines++;
        }
    }
    return lines;
}

static kh_binding make_binding(const char *instance_id, const char *host_key,
                               const char *fqdn, const char *ip) {
    kh_binding binding;

    memset(&binding, 0, sizeof binding);
    snprintf(binding.instance_id, sizeof binding.instance_id, "%s", instance_id);
    snprintf(binding.host_key, sizeof binding.host_key, "%s", host_key);
    snprintf(binding.fqdn, sizeof binding.fqdn, "%s", fqdn);
    snprintf(binding.ip, sizeof binding.ip, "%s", ip);
    return binding;
}

static void test_lock_and_open(void) {
    char *root = make_temp_root();
    char *other_home = make_temp_root();
    state_store *store = NULL;
    char *dir;
    char *known_hosts;

    setenv("XDG_STATE_HOME", root, 1);
    CHECK(state_open("demo", "us-east-1", &store) == 0,
          "state_open succeeds under XDG_STATE_HOME");
    if (store == NULL) {
        free(root);
        free(other_home);
        return;
    }
    dir = strdup(state_dir(store));
    known_hosts = strdup(state_known_hosts_path(store));
    CHECK(dir != NULL && strstr(dir, "/stackctl/demo.us-east-1") != NULL,
          "state dir is <xdg>/stackctl/<project>.<region>");
    CHECK(file_mode(dir) == 0700, "state dir is mode 0700");
    CHECK(known_hosts != NULL && strstr(known_hosts, "known_hosts") != NULL,
          "dedicated known-hosts store lives in the state dir");

    /* Lock is exclusive and times out rather than blocking forever. */
    CHECK(state_lock("demo", "us-east-1", 0) == 0, "first lock succeeds");
    CHECK(strstr(state_lock_path(store), ".lock") != NULL,
          "lock path is the <project>.<region>.lock file");
    {
        int fd = open(state_lock_path(store), O_RDWR);

        CHECK(fd >= 0, "lock file opens");
        if (fd >= 0) {
            CHECK(flock(fd, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK,
                  "lock is exclusive against a second description");
            close(fd);
        }
    }
    CHECK(file_mode(state_lock_path(store)) == 0600, "lock file is mode 0600");
    CHECK(state_lock("demo", "us-east-1", 1) == ETIMEDOUT,
          "second lock attempt expires with ETIMEDOUT");
    CHECK(state_unlock() == 0, "unlock succeeds");
    CHECK(state_unlock() == EBADF, "double unlock reports EBADF");

    state_close(store);

    /* Default base is $HOME/.local/state when XDG_STATE_HOME is unset. */
    unsetenv("XDG_STATE_HOME");
    setenv("HOME", other_home, 1);
    store = NULL;
    CHECK(state_open("other", "eu-west-1", &store) == 0,
          "state_open falls back to HOME/.local/state");
    if (store != NULL) {
        CHECK(strstr(state_dir(store), "/.local/state/stackctl/other.eu-west-1") !=
                  NULL,
              "fallback path derived from HOME");
        state_close(store);
    }

    free(dir);
    free(known_hosts);
    free(root);
    free(other_home);
}

static void test_binding_matrix(void) {
    char *root = make_temp_root();
    state_store *store = NULL;
    kh_binding binding;
    kh_binding got;

    setenv("XDG_STATE_HOME", root, 1);
    CHECK(state_open("demo", "us-east-1", &store) == 0, "store for bindings");
    if (store == NULL) {
        free(root);
        return;
    }

    binding = make_binding("i-111", "AAAAB3NzaC1", "host.example", "198.51.100.1");
    CHECK(state_binding_put(store, &binding) == 0, "put new binding");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-111", &got) == 0, "get binding");
    CHECK(strcmp(got.host_key, "AAAAB3NzaC1") == 0, "stored host key");
    CHECK(strcmp(got.fqdn, "host.example") == 0, "stored fqdn");
    CHECK(strcmp(got.ip, "198.51.100.1") == 0, "stored ip");
    CHECK(file_mode(state_bindings_path(store)) == 0600,
          "binding map is mode 0600");

    /* Same instance-id, changed host key: hard error, never auto-healed. */
    binding = make_binding("i-111", "DIFFERENTKEY", "host.example", "198.51.100.9");
    CHECK(state_binding_put(store, &binding) != 0,
          "same instance-id with changed host key is rejected");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-111", &got) == 0,
          "original binding still present");
    CHECK(strcmp(got.host_key, "AAAAB3NzaC1") == 0,
          "original host key not overwritten");

    /* New instance-id claiming the same FQDN replaces the old binding. */
    binding = make_binding("i-222", "NEWKEY", "host.example", "198.51.100.2");
    CHECK(state_binding_put(store, &binding) == 0,
          "new instance-id claiming the FQDN replaces");
    CHECK(state_binding_get(store, "i-111", &got) == ENOENT,
          "old binding forgotten after FQDN replacement");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-222", &got) == 0 &&
              strcmp(got.host_key, "NEWKEY") == 0,
          "new binding stored");

    /* Unconditional replace + forget. */
    binding = make_binding("i-222", "REKEYED", "host.example", "198.51.100.3");
    CHECK(state_binding_replace(store, &binding) == 0, "explicit replace");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-222", &got) == 0 &&
              strcmp(got.host_key, "REKEYED") == 0,
          "replace overwrites the binding");
    CHECK(state_binding_forget(store, "i-222") == 0, "forget binding");
    CHECK(state_binding_get(store, "i-222", &got) == ENOENT,
          "forgotten binding absent");
    CHECK(state_binding_forget(store, "i-222") == 0,
          "forget is idempotent");

    state_close(store);
    free(root);
}

static void test_logs(void) {
    char *root = make_temp_root();
    state_store *store = NULL;
    state_launch_record record;
    char *content;

    setenv("XDG_STATE_HOME", root, 1);
    CHECK(state_open("demo", "us-east-1", &store) == 0, "store for logs");
    if (store == NULL) {
        free(root);
        return;
    }

    CHECK(state_operations_log_append(
              store, "launch",
              "--password hunter2 DDNS_PASSWORD=s3cr3t PROJECT=demo", "ok") == 0,
          "operations log append");
    CHECK(state_operations_log_append(store, "terminate", "PROJECT=demo", "ok") ==
              0,
          "operations log second append");
    content = read_file(state_operations_log_path(store));
    CHECK(content != NULL, "operations log readable");
    if (content != NULL) {
        CHECK(strstr(content, "launch") != NULL, "verb recorded");
        CHECK(strstr(content, "PROJECT=demo") != NULL, "non-secret args kept");
        CHECK(strstr(content, "hunter2") == NULL, "--password value redacted");
        CHECK(strstr(content, "s3cr3t") == NULL, "secret env value redacted");
        CHECK(strstr(content, "<redacted>") != NULL, "redaction marker present");
        CHECK(count_lines(content) == 2, "append-only, two lines");
        free(content);
    }
    CHECK(file_mode(state_operations_log_path(store)) == 0600,
          "operations log is mode 0600");

    memset(&record, 0, sizeof record);
    snprintf(record.instance_id, sizeof record.instance_id, "i-333");
    snprintf(record.nonce, sizeof record.nonce, "nonce-1");
    snprintf(record.fqdn, sizeof record.fqdn, "host.example");
    snprintf(record.ip, sizeof record.ip, "198.51.100.4");
    snprintf(record.replaced, sizeof record.replaced, "i-222");
    CHECK(state_launch_record_append(store, &record) == 0, "launch record append");
    content = read_file(state_launch_records_path(store));
    CHECK(content != NULL && strstr(content, "i-333") != NULL &&
              strstr(content, "nonce-1") != NULL,
          "launch record persisted");
    free(content);

    CHECK(state_release_history_append(store, "v1.2.3") == 0,
          "release history append");
    content = read_file(state_release_history_path(store));
    CHECK(content != NULL && strstr(content, "v1.2.3") != NULL,
          "release tag persisted");
    free(content);

    state_close(store);
    free(root);
}

int main(void) {
    test_lock_and_open();
    test_binding_matrix();
    test_logs();

    if (failures != 0) {
        fprintf(stderr, "state_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
