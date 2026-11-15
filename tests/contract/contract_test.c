/*
 * contract_test.c — frozen-contract integration tests (CONTRACT.md, spec §4/§8).
 *
 * These tests sit above the module unit tests: they assert the user-visible
 * contract that scripts branch on — the exit-code table, secret redaction,
 * config-validation failure classes, and the known-hosts binding semantics —
 * against the real wave-1 modules (config/state/knownhosts) and the frozen CLI
 * helpers. No network and no AWS.
 */

#include "cli.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/config/config.h"
#include "core/knownhosts/knownhosts.h"
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
/* Exit-code table (spec §4, CONTRACT "Shared conventions")                  */
/* ------------------------------------------------------------------------- */

static void test_exit_code_table(void) {
    CHECK(CLI_EXIT_OK == 0, "exit 0 success");
    CHECK(CLI_EXIT_USAGE == 1, "exit 1 usage/config");
    CHECK(CLI_EXIT_AWS == 2, "exit 2 AWS API");
    CHECK(CLI_EXIT_VERIFY == 3, "exit 3 verification");
    CHECK(CLI_EXIT_LAUNCH == 4, "exit 4 launch failed");
    CHECK(CLI_EXIT_CLEANUP == 5, "exit 5 cleanup incomplete");
    CHECK(CLI_EXIT_FRESHNESS == 6, "exit 6 freshness");
    CHECK(CLI_EXIT_SSH == 7, "exit 7 SSH transport");

    CHECK(cli_rc_to_exit(0) == CLI_EXIT_OK, "rc 0 -> 0");
    CHECK(cli_rc_to_exit(EINVAL) == CLI_EXIT_USAGE, "EINVAL -> 1");
    CHECK(cli_rc_to_exit(ENOENT) == CLI_EXIT_USAGE, "ENOENT -> 1");
    CHECK(cli_rc_to_exit(ETIMEDOUT) == CLI_EXIT_USAGE, "lock timeout -> 1");
    CHECK(cli_rc_to_exit(EACCES) == CLI_EXIT_USAGE, "EACCES -> 1");
    CHECK(cli_rc_to_exit(EPERM) == CLI_EXIT_USAGE, "EPERM -> 1");
    CHECK(cli_rc_to_exit(EIO) == CLI_EXIT_AWS, "EIO -> 2");
    CHECK(cli_rc_to_exit(ECONNREFUSED) == CLI_EXIT_AWS, "ECONNREFUSED -> 2");
}

static void test_verb_table(void) {
    size_t count = 0;
    const char *const *names = cli_verb_names(&count);
    static const char *const expected[] = {
        "provision", "deploy", "refresh-ami", "launch",
        "terminate", "status", "start",        "stop",
    };

    CHECK(names != NULL, "verb table present");
    CHECK(count == sizeof(expected) / sizeof(expected[0]), "eight verbs");
    for (size_t i = 0; i < count && i < sizeof(expected) / sizeof(expected[0]);
         i++) {
        CHECK(strcmp(names[i], expected[i]) == 0, "frozen verb order");
        CHECK(cli_verb_known(names[i]) != 0, "verb known");
    }
    CHECK(cli_verb_known("frobnicate") == 0, "unknown verb rejected");
    /* Only status is lockless; every other verb mutates. */
    CHECK(cli_verb_mutates("status") == 0, "status lockless");
    for (size_t i = 0; i < count; i++) {
        if (strcmp(names[i], "status") != 0) {
            CHECK(cli_verb_mutates(names[i]) != 0, "mutating verb locks");
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Secret redaction (spec §4/§9)                                             */
/* ------------------------------------------------------------------------- */

static void test_redaction(void) {
    char out[512];

    {
        const char *argv[] = {"stackctl", "--password", "hunter2", "launch"};
        CHECK(cli_redact_args(argv, 4, out, sizeof out) == 0, "redact rc");
        CHECK(strstr(out, "hunter2") == NULL, "separate password hidden");
        CHECK(strstr(out, "--password=<redacted>") != NULL, "flag named");
        CHECK(strstr(out, "launch") != NULL, "non-secret kept");
    }
    {
        const char *argv[] = {"stackctl", "--client-secret=abc123", "--json"};
        CHECK(cli_redact_args(argv, 3, out, sizeof out) == 0, "redact eq rc");
        CHECK(strstr(out, "abc123") == NULL, "equals secret hidden");
        CHECK(strstr(out, "--client-secret=<redacted>") != NULL, "eq named");
    }
    {
        const char *argv[] = {"stackctl", "STACKCTL_DDNS_PASSWORD=s3cr3t",
                              "--token", "toksecret"};
        CHECK(cli_redact_args(argv, 4, out, sizeof out) == 0, "redact env rc");
        CHECK(strstr(out, "s3cr3t") == NULL, "env secret hidden");
        CHECK(strstr(out, "toksecret") == NULL, "token operand hidden");
    }
    {
        const char *argv[] = {"provision", "--rotate", "--project",
                              "deploy/aws"};
        CHECK(cli_redact_args(argv, 4, out, sizeof out) == 0, "plain rc");
        CHECK(strcmp(out, "provision --rotate --project deploy/aws") == 0,
              "plain args preserved verbatim");
    }
    {
        const char *argv[] = {"--password", "secret"};
        CHECK(cli_redact_args(argv, 2, out, 8) == ERANGE, "ERANGE on small");
        CHECK(memchr(out, '\0', 8) != NULL, "failure leaves NUL-terminated");
    }
}

/* ------------------------------------------------------------------------- */
/* Config validation fixture (spec §3)                                       */
/* ------------------------------------------------------------------------- */

#define BASE_ENV_AFTER_PROJECT                                                 \
    "REGION=us-east-1\n"                                                       \
    "ARCH=amd64\n"                                                             \
    "SPOT_DEFAULT=false\n"                                                     \
    "AMI_POLICY=pinned\n"                                                      \
    "AMI_ID_AMD64=ami-0123456789abcdef0\n"                                     \
    "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"                                       \
    "ROOT_VOLUME_SIZE=100\n"                                                   \
    "KEY_NAME=demo-key\n"                                                      \
    "SSH_IDENTITY=/home/operator/.ssh/demo\n"                                  \
    "BUCKET_MODULES=artifact,cert\n"                                           \
    "ENABLE_IMAGE_BUILDER=false\n"                                             \
    "SETUP_ENTRYPOINT=deploy.sh\n"                                             \
    "SSH_PORT=22\n"                                                            \
    "SERVICE_UNIT=demo.service\n"                                              \
    "OPERATOR_CIDR=203.0.113.0/24\n"                                           \
    "INGRESS_TCP=443\n"                                                        \
    "INGRESS_UDP=\n"                                                           \
    "RELEASE_TARGETS=//app:deploy.tar.gz\n"                                    \
    "RELEASE_PREFIXES=releases/\n"

#define BASE_ENV "PROJECT=demo\n" BASE_ENV_AFTER_PROJECT

static void mkdir_p(const char *path) {
    char buffer[PATH_MAX];
    size_t length = strlen(path);

    if (length == 0 || length >= sizeof buffer) {
        exit(1);
    }
    memcpy(buffer, path, length + 1);
    for (char *p = buffer + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            (void)mkdir(buffer, 0777);
            *p = '/';
        }
    }
    (void)mkdir(buffer, 0777);
}

static void write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    fputs(text, file);
    fclose(file);
}

typedef struct config_fixture {
    char root[PATH_MAX];
    char config_dir[PATH_MAX];
} config_fixture;

static void config_fixture_init(config_fixture *fx) {
    char template[] = "/tmp/stackctl-contract-XXXXXX";
    char *root = mkdtemp(template);
    char path[PATH_MAX];

    memset(fx, 0, sizeof *fx);
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof fx->root, "%s", root);
    snprintf(fx->config_dir, sizeof fx->config_dir, "%s/deploy/aws", fx->root);
    mkdir_p(fx->config_dir);
    snprintf(path, sizeof path, "%s/MODULE.bazel", fx->root);
    write_text(path, "");
}

static void write_env_file(const config_fixture *fx, const char *name,
                           const char *body) {
    char path[PATH_MAX];

    snprintf(path, sizeof path, "%s/%s", fx->config_dir, name);
    write_text(path, body);
}

static void write_project_env(const config_fixture *fx, const char *project) {
    char body[8192];

    snprintf(body, sizeof body, "PROJECT=%s\n%s", project,
             BASE_ENV_AFTER_PROJECT);
    write_env_file(fx, ".env", body);
}

static void test_config_validation(void) {
    config_fixture fx;
    stackctl_config *cfg = NULL;

    config_fixture_init(&fx);

    /* Baseline: the documented minimal config loads. */
    write_env_file(&fx, ".env", BASE_ENV);
    CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == 0, "valid .env loads");
    CHECK(cfg != NULL, "valid .env returns config");
    if (cfg != NULL) {
        CHECK(strcmp(config_project(cfg), "demo") == 0, "project parsed");
        CHECK(strcmp(config_region(cfg), "us-east-1") == 0, "region parsed");
    }
    config_free(cfg);
    cfg = NULL;

    /* Unknown keys are errors, never warnings (fail-closed). */
    {
        char body[8192];

        snprintf(body, sizeof body, "%sTOTALLY_UNKNOWN=1\n", BASE_ENV);
        write_env_file(&fx, ".env", body);
    }
    CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == EINVAL,
          "unknown key rejected");
    CHECK(cfg == NULL, "unknown key leaves out untouched");

    /* PROJECT regex: ^[a-z][a-z0-9]+$ (no hyphen, uppercase, leading digit). */
    static const char *const bad_projects[] = {"Demo", "de-mo", "9demo", "d",
                                               "demo_app", NULL};
    for (size_t i = 0; bad_projects[i] != NULL; i++) {
        write_project_env(&fx, bad_projects[i]);
        cfg = NULL;
        CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == EINVAL,
              "invalid PROJECT rejected");
        CHECK(cfg == NULL, "invalid PROJECT leaves out untouched");
    }

    /* Per-region bucket-name bound: a very long valid PROJECT is rejected. */
    {
        char project[80];

        memset(project, 'a', sizeof project - 1);
        project[sizeof project - 1] = '\0';
        project[0] = 'p';
        write_project_env(&fx, project);
        cfg = NULL;
        CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == EINVAL,
              "over-long PROJECT rejected by bucket bound");
    }

    /* --region must select a variant that declares the same REGION. */
    write_env_file(&fx, ".env", BASE_ENV);
    write_env_file(&fx, ".env.eu-west-1", BASE_ENV);
    cfg = NULL;
    CHECK(config_load(fx.config_dir, 1, "eu-west-1", &cfg) == EINVAL,
          "variant REGION mismatch rejected");
    /* A plain .env whose REGION has a variant sibling demands --region. */
    write_env_file(&fx, ".env.us-east-1", BASE_ENV);
    cfg = NULL;
    CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == EINVAL,
          "ambiguous plain .env rejected when sibling exists");

    /* AMI_POLICY=ssm must not carry a pinned AMI id. */
    {
        char body[8192];

        snprintf(body, sizeof body,
                 "PROJECT=demo\nREGION=us-east-1\nARCH=amd64\n"
                 "SPOT_DEFAULT=false\nAMI_POLICY=ssm\n"
                 "AMI_SSM_AMD64=/demo/ami/amd64\n"
                 "AMI_ID_AMD64=ami-0123456789abcdef0\n"
                 "INSTANCE_TYPES_AMD64=g4dn.xlarge\nROOT_VOLUME_SIZE=100\n"
                 "KEY_NAME=k\nSSH_IDENTITY=/k\nBUCKET_MODULES=artifact\n"
                 "ENABLE_IMAGE_BUILDER=false\nSETUP_ENTRYPOINT=deploy.sh\n"
                 "SSH_PORT=22\nOPERATOR_CIDR=\nINGRESS_TCP=443\n"
                 "INGRESS_UDP=\nRELEASE_TARGETS=//a\n"
                 "RELEASE_PREFIXES=releases/\n");
        write_env_file(&fx, ".env", body);
        cfg = NULL;
        CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == EINVAL,
              "ssm policy with AMI_ID_* rejected");
    }

    /* DDNS_HOST and DDNS_DOMAIN travel together. */
    {
        char body[8192];

        snprintf(body, sizeof body, "%sDDNS_HOST=app\n", BASE_ENV);
        write_env_file(&fx, ".env", body);
        cfg = NULL;
        CHECK(config_load(fx.config_dir, 0, NULL, &cfg) == EINVAL,
              "DDNS host without domain rejected");
    }
}

/* ------------------------------------------------------------------------- */
/* Known-hosts binding contract (spec §8)                                    */
/* ------------------------------------------------------------------------- */

static char *make_temp_root(const char *prefix) {
    char template[128];
    char *root;

    snprintf(template, sizeof template, "/tmp/stackctl-%s-XXXXXX", prefix);
    root = mkdtemp(template);
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

static char *read_text_file(const char *path) {
    FILE *file = fopen(path, "rb");
    char *buffer;
    long size;

    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    buffer = calloc((size_t)size + 1, 1);
    if (buffer == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        buffer = NULL;
    }
    fclose(file);
    return buffer;
}

#define KEY_ONE                                                                \
    "10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOneKeyMaterialForTests"
#define KEY_TWO                                                                \
    "10.0.0.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITwoKeyMaterialForTests"

static void test_knownhosts_contract(void) {
    char *root = make_temp_root("contract-kh");
    char *store = join_path(root, "known_hosts");
    char *content;

    CHECK(kh_bound(store, "i-new") == false, "unbound before pin");
    CHECK(kh_pin(store, "i-abc", KEY_ONE) == 0, "pin first key");
    CHECK(kh_bound(store, "i-abc") == true, "bound after pin");
    /* Same instance-id + same key is an idempotent no-op. */
    CHECK(kh_pin(store, "i-abc", KEY_ONE) == 0, "same key no-op");
    /* Same instance-id + changed key is a hard error (possible compromise). */
    CHECK(kh_pin(store, "i-abc", KEY_TWO) == EPERM,
          "changed key for same instance is EPERM");
    content = read_text_file(store);
    CHECK(content != NULL, "store readable");
    if (content != NULL) {
        CHECK(strstr(content, "i-abc") != NULL, "alias keyed by instance id");
        CHECK(strstr(content, "OneKeyMaterial") != NULL,
              "original key retained after refusal");
        CHECK(strstr(content, "TwoKeyMaterial") == NULL,
              "changed key never written");
        free(content);
    }
    /* Forgetting one instance must not damage other pinned entries: the
     * store is multi-entry, and launch relies on this when replacing an
     * instance (it forgets the old id after pinning the new one). */
    CHECK(kh_pin(store, "i-other", KEY_TWO) == 0, "pin second key");
    CHECK(kh_forget(store, "i-abc") == 0, "forget one binding");
    CHECK(kh_bound(store, "i-abc") == false, "forgotten binding gone");
    CHECK(kh_bound(store, "i-other") == true, "other binding survives");
    content = read_text_file(store);
    CHECK(content != NULL, "store readable after forget");
    if (content != NULL) {
        CHECK(strstr(content, "TwoKeyMaterial") != NULL,
              "surviving binding keeps its key material");
        free(content);
    }
    CHECK(kh_forget(store, "i-abc") == 0, "forget is idempotent");

    free(store);
    free(root);
}

static void test_state_binding_contract(void) {
    char *root = make_temp_root("contract-state");
    state_store *store = NULL;
    kh_binding first;
    kh_binding second;
    kh_binding got;

    if (setenv("XDG_STATE_HOME", root, 1) != 0) {
        perror("setenv");
        exit(1);
    }
    CHECK(state_open("demo", "us-east-1", &store) == 0, "state opens");
    if (store == NULL) {
        free(root);
        return;
    }

    memset(&first, 0, sizeof first);
    snprintf(first.instance_id, sizeof first.instance_id, "%s", "i-111");
    snprintf(first.host_key, sizeof first.host_key, "%s", "KEY-ONE");
    snprintf(first.fqdn, sizeof first.fqdn, "%s", "app.example.com");
    snprintf(first.ip, sizeof first.ip, "%s", "10.1.0.1");
    CHECK(state_binding_put(store, &first) == 0, "first binding stored");

    /* A new instance-id claiming the same FQDN replaces the old binding. */
    memset(&second, 0, sizeof second);
    snprintf(second.instance_id, sizeof second.instance_id, "%s", "i-222");
    snprintf(second.host_key, sizeof second.host_key, "%s", "KEY-TWO");
    snprintf(second.fqdn, sizeof second.fqdn, "%s", "app.example.com");
    snprintf(second.ip, sizeof second.ip, "%s", "10.1.0.2");
    CHECK(state_binding_put(store, &second) == 0, "new instance replaces fqdn");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-111", &got) == ENOENT,
          "replaced binding gone");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-222", &got) == 0, "new binding present");
    CHECK(strcmp(got.fqdn, "app.example.com") == 0, "fqdn carried over");

    /* Same instance-id presenting a changed key is a hard error. */
    snprintf(second.host_key, sizeof second.host_key, "%s", "KEY-CHANGED");
    CHECK(state_binding_put(store, &second) == EPERM,
          "same id changed key is EPERM");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-222", &got) == 0, "old binding intact");
    CHECK(strcmp(got.host_key, "KEY-TWO") == 0, "host key never auto-healed");

    CHECK(state_binding_forget(store, "i-222") == 0, "binding forgotten");
    memset(&got, 0, sizeof got);
    CHECK(state_binding_get(store, "i-222", &got) == ENOENT,
          "forgotten binding absent");

    state_close(store);
    free(root);
}

int main(void) {
    test_exit_code_table();
    test_verb_table();
    test_redaction();
    test_config_validation();
    test_knownhosts_contract();
    test_state_binding_contract();

    if (failures != 0) {
        fprintf(stderr, "%d contract test(s) failed\n", failures);
        return 1;
    }
    printf("contract_test: ok\n");
    return 0;
}
