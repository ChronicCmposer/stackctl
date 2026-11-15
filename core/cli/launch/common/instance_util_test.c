/*
 * instance_util_test.c — unit tests for the pure instance-verb helpers:
 * base64, host-key fingerprints, manifest selection, arch/type resolution,
 * state classification and small utilities, plus the production services
 * wiring's abort-hook installation. No network; the services test uses a fake
 * credentials file under a temporary HOME.
 */

#include "instance.h"

#include "aws_internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void test_base64(void) {
    const unsigned char raw[] = {'M', 'a', 'n'};
    char encoded[16];
    unsigned char decoded[16];
    size_t decoded_len = 0;

    CHECK(instance_base64_encode(raw, sizeof raw, encoded, sizeof encoded) == 0,
          "encode returns 0");
    CHECK(strcmp(encoded, "TWFu") == 0, "encode 'Man' == TWFu");
    CHECK(instance_base64_decode(encoded, decoded, sizeof decoded,
                                 &decoded_len) == 0,
          "decode returns 0");
    CHECK(decoded_len == 3 && memcmp(decoded, raw, 3) == 0,
          "decode round-trips");

    CHECK(instance_base64_encode((const unsigned char *)"M", 1, encoded,
                                 sizeof encoded) == 0,
          "encode single byte");
    CHECK(strcmp(encoded, "TQ==") == 0, "single byte padded");

    CHECK(instance_base64_encode((const unsigned char *)"", 0, encoded,
                                 sizeof encoded) == 0,
          "encode empty");
    CHECK(encoded[0] == '\0', "empty encoding empty string");

    CHECK(instance_base64_encode(raw, sizeof raw, encoded, 4) == ENAMETOOLONG,
          "small buffer rejected");
}

static void test_fingerprint(void) {
    /* Real ed25519 key blob base64 (32-byte key + framing). */
    const char *line =
        "203.0.113.9 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIJ8Lk7v5H0m0b2w7p8eQ0f3o5w5m6v8j3h9r2s1t4u6v";
    char first[INST_FINGERPRINT_MAX];
    char second[INST_FINGERPRINT_MAX];
    char other[INST_FINGERPRINT_MAX];

    CHECK(instance_key_fingerprint(line, first, sizeof first) == 0,
          "fingerprint returns 0");
    CHECK(strncmp(first, "SHA256:", 7) == 0, "fingerprint prefix");
    CHECK(strchr(first, '=') == NULL, "fingerprint has no base64 padding");
    CHECK(instance_key_fingerprint(line, second, sizeof second) == 0,
          "fingerprint repeat");
    CHECK(strcmp(first, second) == 0, "fingerprint deterministic");
    CHECK(instance_key_fingerprint(
              "ssh-ed25519 "
              "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              other, sizeof other) == 0,
          "second key fingerprint");
    CHECK(strcmp(first, other) != 0, "different keys differ");
    CHECK(instance_key_fingerprint("garbage", first, sizeof first) == EINVAL,
          "malformed line rejected");
}

static void test_console_fingerprints(void) {
    const char *console =
        "cloud-init v.24.1\n"
        "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
        "256 SHA256:aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk root (ED25519)\n"
        "256 SHA256:zzzzyyyyxxxxwwwwvvvvuuuuttttssssrrrrqqqqpppp root (ECDSA)\n"
        "-----END SSH HOST KEY FINGERPRINTS-----\n";
    char prints[4][INST_FINGERPRINT_MAX];
    size_t count = 0;

    CHECK(instance_console_fingerprints(console, prints, 4, &count) == 0,
          "console parse returns 0");
    CHECK(count == 2, "two fingerprints extracted");
    CHECK(strcmp(prints[0], "SHA256:aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk") ==
              0,
          "first fingerprint exact");
    CHECK(instance_console_fingerprints("no keys here\n", prints, 4, &count) ==
              0,
          "no-key console returns 0");
    CHECK(count == 0, "no fingerprints found");
}

static void test_manifest(void) {
    const char *manifest =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  "
        "app-deployment-go-amd64.tar\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  "
        "app-deployment-go-arm64.tar\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  "
        "app-deployment-c-amd64.tar\n";
    char member[128];
    char sha[68];
    char choices[256];

    CHECK(instance_manifest_select(manifest, "go", "amd64", member,
                                   sizeof member, sha, sizeof sha, NULL, 0) ==
              0,
          "manifest selects explicit variant");
    CHECK(strcmp(member, "app-deployment-go-amd64.tar") == 0,
          "selected go/amd64 member");
    CHECK(strncmp(sha, "aaaaaaaa", 8) == 0, "selected go/amd64 sha");

    CHECK(instance_manifest_select(manifest, NULL, "arm64", member,
                                   sizeof member, sha, sizeof sha, NULL, 0) ==
              0,
          "manifest selects single arch match");
    CHECK(strcmp(member, "app-deployment-go-arm64.tar") == 0,
          "arm64 unambiguous");

    memset(choices, 0, sizeof choices);
    CHECK(instance_manifest_select(manifest, NULL, "amd64", member,
                                   sizeof member, sha, sizeof sha, choices,
                                   sizeof choices) == EINVAL,
          "ambiguous arch without variant rejected");
    CHECK(strstr(choices, "app-deployment-go-amd64.tar") != NULL &&
              strstr(choices, "app-deployment-c-amd64.tar") != NULL,
          "ambiguity choices name every matching member");

    CHECK(instance_manifest_select(manifest, "c", "arm64", member,
                                   sizeof member, sha, sizeof sha, NULL, 0) ==
              ENOENT,
          "missing variant/arch combo is ENOENT");
}

static void test_tool_available(void) {
    char template[] = "/tmp/stackctl-tool-XXXXXX";
    char *dir = mkdtemp(template);
    char path[PATH_MAX];
    char *saved = getenv("PATH") != NULL ? strdup(getenv("PATH")) : NULL;
    FILE *file;

    CHECK(dir != NULL, "tool test temp dir");
    if (dir == NULL) {
        free(saved);
        return;
    }
    snprintf(path, sizeof path, "%s/stackctl-fake-tool", dir);
    file = fopen(path, "w");
    CHECK(file != NULL, "tool test file created");
    if (file != NULL) {
        fputs("#!/bin/sh\nexit 0\n", file);
        fclose(file);
    }
    CHECK(chmod(path, 0755) == 0, "tool test file executable");

    CHECK(setenv("PATH", dir, 1) == 0, "tool test PATH set");
    CHECK(instance_tool_available("stackctl-fake-tool") == 1,
          "tool_available finds an executable on PATH");
    CHECK(instance_tool_available("stackctl-missing-tool") == 0,
          "tool_available rejects a missing tool");
    CHECK(instance_tool_available(NULL) == 0,
          "tool_available rejects a NULL name");

    if (saved != NULL) {
        CHECK(setenv("PATH", saved, 1) == 0, "tool test PATH restored");
        free(saved);
    } else {
        unsetenv("PATH");
    }
    unlink(path);
    rmdir(dir);
}

static void test_arch(void) {
    char out[16];
    const char *why = NULL;

    CHECK(instance_select_arch("amd64", NULL, out, sizeof out, &why) == 0 &&
              strcmp(out, "amd64") == 0,
          "single arch resolved");
    CHECK(instance_select_arch("amd64", "amd64", out, sizeof out, &why) == 0,
          "matching flag accepted");
    CHECK(instance_select_arch("amd64", "arm64", out, sizeof out, &why) ==
              EINVAL,
          "mismatched flag rejected");
    CHECK(instance_select_arch("both", NULL, out, sizeof out, &why) == EINVAL,
          "both requires --arch");
    CHECK(why != NULL && strstr(why, "--arch") != NULL,
          "both rejection explains --arch");
    CHECK(instance_select_arch("both", "arm64", out, sizeof out, &why) == 0 &&
              strcmp(out, "arm64") == 0,
          "both+flag resolved");
}

static void test_types(void) {
    instance_config cfg;
    char out[64];

    memset(&cfg, 0, sizeof cfg);
    strcpy(cfg.instance_types_amd64, "g4dn.xlarge, g6.xlarge");
    strcpy(cfg.instance_types_arm64, "g5g.2xlarge");

    CHECK(instance_resolve_type(&cfg, "amd64", NULL, out, sizeof out) == 0,
          "default type returns 0");
    CHECK(strcmp(out, "g4dn.xlarge") == 0, "first allowlisted type");
    CHECK(instance_resolve_type(&cfg, "amd64", "g6.xlarge", out, sizeof out) ==
              0,
          "allowlisted type accepted");
    CHECK(instance_resolve_type(&cfg, "amd64", "m5.large", out, sizeof out) ==
              EINVAL,
          "non-allowlisted type rejected");
    CHECK(instance_resolve_type(&cfg, "arm64", "g5g.2xlarge", out, sizeof out) ==
              0,
          "arm64 type accepted");
}

static void test_misc(void) {
    int seconds = 0;
    char fqdn[128];
    char token[65];
    char nonce[33];
    ec2_instance_list list;
    ec2_instance items[2];

    CHECK(instance_state_active("running"), "running is active");
    CHECK(instance_state_active("stopped"), "stopped is active");
    CHECK(!instance_state_active("terminated"), "terminated not active");
    CHECK(instance_state_terminable("shutting-down"), "shutting-down terminable");
    CHECK(!instance_state_terminable("terminated"), "terminated not terminable");

    CHECK(instance_parse_seconds("300", &seconds) == 0 && seconds == 300,
          "seconds parsed");
    CHECK(instance_parse_seconds("0", &seconds) == EINVAL, "zero rejected");
    CHECK(instance_parse_seconds("abc", &seconds) == EINVAL, "text rejected");

    CHECK(instance_fqdn("box", "example.com", fqdn, sizeof fqdn) == 0,
          "fqdn returns 0");
    CHECK(strcmp(fqdn, "box.example.com") == 0, "label joined");
    CHECK(instance_fqdn("api.example.com", "example.com", fqdn, sizeof fqdn) ==
              0 &&
              strcmp(fqdn, "api.example.com") == 0,
          "fqdn preserved");

    CHECK(instance_client_token("proj", "abc", token) == 0, "token returns 0");
    CHECK(strlen(token) == 64, "token is 64 hex chars");
    CHECK(instance_nonce(nonce) == 0 && strlen(nonce) == 32,
          "nonce is 32 hex chars");

    memset(items, 0, sizeof items);
    strcpy(items[0].instance_id, "i-1");
    strcpy(items[0].public_ip, "198.51.100.7");
    strcpy(items[0].state, "running");
    strcpy(items[1].instance_id, "i-2");
    strcpy(items[1].public_ip, "198.51.100.8");
    strcpy(items[1].state, "terminated");
    list.items = items;
    list.count = 2;

    CHECK(strcmp(instance_restore_ip("198.51.100.7", &list), "198.51.100.7") ==
              0,
          "restore to live instance ip");
    CHECK(strcmp(instance_restore_ip("198.51.100.8", &list), "0.0.0.0") == 0,
          "park when snapshot ip is not live");
    CHECK(instance_find(&list, "i-2") == &items[1], "find by id");
    CHECK(instance_find(&list, "i-x") == NULL, "missing id is NULL");
}

static char *make_credentials_home(void) {
    char *home = strdup("/tmp/stackctl-services-XXXXXX");
    char dir[PATH_MAX];
    char path[PATH_MAX];
    FILE *file;

    if (home == NULL || mkdtemp(home) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    if (snprintf(dir, sizeof dir, "%s/.aws", home) >= (int)sizeof dir ||
        mkdir(dir, 0700) != 0) {
        perror("mkdir .aws");
        exit(2);
    }
    if (snprintf(path, sizeof path, "%s/credentials", dir) >= (int)sizeof path) {
        exit(2);
    }
    file = fopen(path, "w");
    if (file == NULL) {
        perror("fopen credentials");
        exit(2);
    }
    fputs("[prod-abort]\n"
          "aws_access_key_id = AKIAFAKEFAKEFAKEFAKE\n"
          "aws_secret_access_key = fake-secret\n",
          file);
    if (fclose(file) != 0) {
        exit(2);
    }
    return home;
}

static void test_services_install_abort_hook(void) {
    char *home = make_credentials_home();
    const char *saved_home = getenv("HOME");
    char *saved = saved_home != NULL ? strdup(saved_home) : NULL;
    instance_services svc;
    int rc;

    CHECK(setenv("HOME", home, 1) == 0, "HOME points at fake credentials");
    rc = instance_services_open(&svc, "prod-abort", "us-east-1");
    CHECK(rc == 0, "production services open");
    if (rc == 0) {
        CHECK(svc.aws != NULL, "production services expose a client");
        CHECK(svc.aws != NULL && svc.aws->abort_fn == cli_abort_check,
              "production services install the CLI abort hook");
        CHECK(svc.aws != NULL && svc.aws->abort_ud == NULL,
              "abort hook has no user data");
        instance_services_close(&svc);
    }
    if (saved != NULL) {
        CHECK(setenv("HOME", saved, 1) == 0, "HOME restored");
        free(saved);
    } else {
        unsetenv("HOME");
    }
}

int main(void) {
    test_services_install_abort_hook();
    test_base64();
    test_fingerprint();
    test_console_fingerprints();
    test_manifest();
    test_tool_available();
    test_arch();
    test_types();
    test_misc();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all instance util tests passed\n");
    return 0;
}
