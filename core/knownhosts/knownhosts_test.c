/*
 * knownhosts_test.c — unit tests for core/knownhosts (spec §8).
 *
 * Covers pin/bound/forget, alias rewriting, idempotence, the same-instance-id
 * changed-key hard error, 0600 mode, and never writing ~/.ssh/known_hosts.
 */

#include "knownhosts.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char template[] = "/tmp/stackctl-kh-XXXXXX";
    char *root = mkdtemp(template);

    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    return strdup(root);
}

static char *join_path(const char *dir, const char *name) {
    size_t need = strlen(dir) + strlen(name) + 2;
    char *path = malloc(need);

    if (path == NULL) {
        perror("malloc");
        exit(1);
    }
    snprintf(path, need, "%s/%s", dir, name);
    return path;
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

int main(void) {
    char *root = make_temp_root();
    char *home = make_temp_root();
    char *store = join_path(root, "known_hosts");
    char *home_ssh = join_path(home, ".ssh");
    char *home_known = join_path(home_ssh, "known_hosts");
    const char *key_ed25519 = "AAAAC3NzaC1lZDI1NTE5AAAA";
    const char *key_rsa = "AAAAB3NzaC1yc2EAAAADAQAB";
    char *content;

    setenv("HOME", home, 1);
    CHECK(mkdir(home_ssh, 0700) == 0, "test ~/.ssh created");

    CHECK(!kh_bound(store, "i-abc"), "unbound before pin (missing store)");
    CHECK(kh_pin(store, "i-abc", "198.51.100.7 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA") ==
              0,
          "pin scanned key");
    CHECK(kh_bound(store, "i-abc"), "bound after pin");
    CHECK(file_mode(store) == 0600, "store is mode 0600");
    content = read_file(store);
    CHECK(content != NULL, "store readable");
    if (content != NULL) {
        CHECK(strstr(content, "i-abc ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA") !=
                  NULL,
              "entry rewritten under the instance-id alias");
        CHECK(strstr(content, "198.51.100.7") == NULL,
              "public IP is not written into the store");
        CHECK(count_lines(content) == 1, "one entry");
        free(content);
    }
    CHECK(access(home_known, F_OK) != 0,
          "~/.ssh/known_hosts is never written");

    /* Idempotent re-pin of identical material. */
    CHECK(kh_pin(store, "i-abc", "198.51.100.7 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA") ==
              0,
          "re-pin identical key succeeds");
    content = read_file(store);
    CHECK(content != NULL && count_lines(content) == 1, "no duplicate entry");
    free(content);

    /* Same instance-id, changed host key: hard error, store untouched. */
    CHECK(kh_pin(store, "i-abc", "198.51.100.7 ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB") !=
              0,
          "changed key for same instance-id is rejected");
    content = read_file(store);
    CHECK(content != NULL, "store readable after rejected pin");
    if (content != NULL) {
        CHECK(strstr(content, key_ed25519) != NULL,
              "original ed25519 key retained");
        CHECK(strstr(content, key_rsa) == NULL, "rejected rsa key not written");
        CHECK(count_lines(content) == 1, "still one entry");
        free(content);
    }

    /* A second instance-id gets its own alias entry. */
    CHECK(kh_pin(store, "i-def", "198.51.100.8 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA") ==
              0,
          "pin second instance");
    CHECK(kh_bound(store, "i-abc") && kh_bound(store, "i-def"),
          "both instances bound");
    content = read_file(store);
    CHECK(content != NULL && count_lines(content) == 2, "two entries");
    free(content);

    /* An already-aliased scanned line is accepted verbatim. */
    CHECK(kh_pin(store, "i-xyz", "i-xyz ssh-ed25519 AAAAALREADYALIASED") == 0,
          "already-aliased line accepted");
    CHECK(kh_bound(store, "i-xyz"), "aliased instance bound");

    CHECK(kh_forget(store, "i-abc") == 0, "forget instance");
    CHECK(!kh_bound(store, "i-abc"), "forgotten instance unbound");
    CHECK(kh_bound(store, "i-def") && kh_bound(store, "i-xyz"),
          "other bindings preserved");

    /* Forgetting one binding must leave every *retained* line byte-intact:
     * the id and the key material of the other entries must survive verbatim.
     * Regression: split_first() used to NUL-terminate the first field in place
     * and then copy the truncated pointer, leaving bare instance-ids. */
    content = read_file(store);
    CHECK(content != NULL, "store readable after forgetting one binding");
    if (content != NULL) {
        CHECK(strstr(content,
                     "i-def ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n") != NULL,
              "retained i-def keeps id and key material");
        CHECK(strstr(content, "i-xyz ssh-ed25519 AAAAALREADYALIASED\n") != NULL,
              "retained i-xyz keeps id and key material");
        CHECK(strstr(content, "i-abc") == NULL, "forgotten entry removed");
        CHECK(count_lines(content) == 2, "two entries retained after forget");
        free(content);
    }

    /* A retained id whose line kept its key can still be re-pinned (no-op). A
     * truncated line would make this look like a changed-key conflict (EPERM). */
    CHECK(kh_pin(store, "i-def",
                 "198.51.100.8 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA") == 0,
          "re-pin a retained id after forget does not EPERM");
    CHECK(kh_pin(store, "i-xyz", "i-xyz ssh-ed25519 AAAAALREADYALIASED") == 0,
          "re-pin aliased retained id after forget does not EPERM");

    CHECK(kh_forget(store, "i-abc") == 0, "forget is idempotent");

    CHECK(kh_pin(NULL, "i-abc", "host ssh-ed25519 AAA") == EINVAL,
          "NULL store rejected");
    CHECK(kh_pin(store, "", "host ssh-ed25519 AAA") == EINVAL,
          "empty instance-id rejected");
    CHECK(kh_pin(store, "i-abc", "") == EINVAL, "empty scanned line rejected");
    CHECK(kh_pin(store, "i-abc", "onlyhost") == EINVAL,
          "incomplete scanned line rejected");

    free(home_known);
    free(home_ssh);
    free(store);
    free(home);
    free(root);
    if (failures != 0) {
        fprintf(stderr, "knownhosts_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
