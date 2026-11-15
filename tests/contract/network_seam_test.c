/*
 * network_seam_test.c — runtime/link check for the closed network seam (spec §9).
 *
 * The design allows network symbols only in core/aws, core/ddns, core/dns (and
 * the status IP-echo call site). This test links every non-transport module
 * into one binary with its own poison definitions of the libc socket/DNS entry
 * points, then drives their fake-transport surfaces. Any accidental direct
 * socket/DNS call from those modules resolves here instead of libc and fails
 * the assertion; libcurl and c-ares are only reachable through core/aws and
 * core/dns, which this target does not drive. No real sockets are opened.
 */

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/aws/aws.h"
#include "core/cfn/cfn.h"
#include "core/cfn/cfn_internal.h"
#include "core/cli/common/cli.h"
#include "core/config/config.h"
#include "core/crypto/crypto.h"
#include "core/ec2/ec2.h"
#include "core/ini/ini.h"
#include "core/knownhosts/knownhosts.h"
#include "core/s3/s3.h"
#include "core/s3/s3_internal.h"
#include "core/ssm/ssm.h"
#include "core/state/state.h"

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ------------------------------------------------------------------------- */
/* Poisoned network entry points                                             */
/* ------------------------------------------------------------------------- */

static int calls_socket;
static int calls_connect;
static int calls_getaddrinfo;
static int calls_gethostbyname;

int socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    calls_socket++;
    errno = EACCES;
    return -1;
}

int connect(int fd, const void *addr, unsigned int len) {
    (void)fd;
    (void)addr;
    (void)len;
    calls_connect++;
    errno = ECONNREFUSED;
    return -1;
}

int getaddrinfo(const char *node, const char *service, const void *hints,
                void **res) {
    (void)node;
    (void)service;
    (void)hints;
    (void)res;
    calls_getaddrinfo++;
    return -1;
}

void *gethostbyname(const char *name) {
    (void)name;
    calls_gethostbyname++;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Fake transports                                                           */
/* ------------------------------------------------------------------------- */

static int fake_cfn_send(aws_ctx *ctx, const aws_req *req, aws_resp *resp,
                         void *ud) {
    (void)ctx;
    (void)req;
    (void)ud;
    memset(resp, 0, sizeof *resp);
    return ENOENT;
}

static int fake_s3_send(void *ud, const aws_req *req, aws_resp *resp) {
    (void)ud;
    (void)req;
    memset(resp, 0, sizeof *resp);
    return ENOENT;
}

static void mkdir_p(const char *path) {
    char buffer[512];
    size_t length = strlen(path);

    if (length == 0 || length >= sizeof buffer) {
        return;
    }
    memcpy(buffer, path, length + 1);
    for (char *p = buffer + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(buffer, 0700);
            *p = '/';
        }
    }
    (void)mkdir(buffer, 0700);
}

/* Remove a temporary tree without invoking host tools (Amendment 4). */
static void remove_tree(const char *path) {
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(path, &st) != 0) {
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path);
        return;
    }
    dir = opendir(path);
    if (dir != NULL) {
        while ((entry = readdir(dir)) != NULL) {
            char child[PATH_MAX];

            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            if (snprintf(child, sizeof child, "%s/%s", path, entry->d_name) >=
                (int)sizeof child) {
                continue;
            }
            remove_tree(child);
        }
        closedir(dir);
    }
    (void)rmdir(path);
}

static int no_network_calls(void) {
    return calls_socket == 0 && calls_connect == 0 && calls_getaddrinfo == 0 &&
           calls_gethostbyname == 0;
}

int main(void) {
    char root[] = "/tmp/stackctl-seam-XXXXXX";
    char state_root[512];
    char store[512];
    char ini_path[512];

    if (mkdtemp(root) == NULL) {
        perror("mkdtemp");
        return 1;
    }

    /* crypto: pure computation */
    {
        uint8_t digest[32];
        crypto_sha256("abc", 3, digest);
        CHECK(digest[0] == 0xba, "sha256 of abc");
    }

    /* ini: one atomic section upsert */
    snprintf(ini_path, sizeof ini_path, "%s/credentials", root);
    {
        char *backup = NULL;
        int rc = ini_upsert_section(ini_path, "demo", "aws_access_key_id",
                                    "AKIATEST", &backup);
        CHECK(rc == 0, "ini upsert");
        free(backup);
    }

    /* knownhosts */
    snprintf(store, sizeof store, "%s/known_hosts", root);
    CHECK(kh_pin(store, "i-seam",
                 "10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISeamKey") ==
              0,
          "kh pin");
    CHECK(kh_bound(store, "i-seam"), "kh bound");

    /* state */
    snprintf(state_root, sizeof state_root, "%s/state", root);
    mkdir_p(state_root);
    if (setenv("XDG_STATE_HOME", state_root, 1) != 0) {
        perror("setenv");
        return 1;
    }
    {
        state_store *state = NULL;
        CHECK(state_open("seam", "us-east-1", &state) == 0, "state open");
        state_close(state);
    }

    /* Service clients constructed over fake transports never reach the wire. */
    {
        cfn_client *cfn = NULL;
        ec2_client *ec2 = NULL;
        ssm_client *ssm = NULL;
        s3_client *s3 = NULL;

        CHECK(cfn_client_create_with_transport(&cfn, NULL, fake_cfn_send,
                                               NULL) == 0,
              "cfn fake client");
        cfn_client_destroy(cfn);
        /* Client constructors require a real aws_ctx; NULL is a safe
         * argument check, and the free path keeps the modules linked. */
        CHECK(ec2_client_init(&ec2, NULL, "us-east-1") == EINVAL,
              "ec2 rejects a NULL aws context");
        ec2_client_free(ec2);
        CHECK(ssm_client_init(&ssm, NULL, "us-east-1") == EINVAL,
              "ssm rejects a NULL aws context");
        ssm_client_free(ssm);
        CHECK(s3_client_init_with_transport(&s3, "us-east-1", fake_s3_send,
                                            NULL) == 0,
              "s3 fake client");
        s3_client_free(s3);
    }

    /* CLI substrate is pure: parsing and redaction allocate no sockets. */
    {
        char out[256];
        const char *argv[] = {"stackctl", "--json", "--token", "xyz"};
        CHECK(cli_redact_args(argv, 4, out, sizeof out) == 0, "redact");
        CHECK(strstr(out, "xyz") == NULL, "token hidden");
    }

    CHECK(no_network_calls(), "no network calls from non-transport modules");

    remove_tree(root);
    {
        struct stat st;

        if (lstat(root, &st) == 0) {
            fprintf(stderr, "warning: cleanup failed for %s\n", root);
        }
    }

    if (failures != 0) {
        fprintf(stderr, "%d network-seam check(s) failed\n", failures);
        return 1;
    }
    printf("network_seam_test: ok\n");
    return 0;
}
