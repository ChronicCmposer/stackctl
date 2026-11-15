/*
 * startstop_test.c — orchestration tests for `stackctl start`/`stop` driven by
 * an injected services vtable. Covers target selection, host-key re-verification
 * policy, TOFU flag, argv shape, exit codes and transport failures.
 */

#include "startstop_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* --- fakes --------------------------------------------------------------- */

static ec2_instance fixtures[8];
static size_t fixture_count;
static int g_bound;
static char g_key_line[512];
static char g_console[1024];
static int g_console_present;
static int g_keyscan_null;
static int g_ssh_fail;
static int g_remote_rc;
static char g_argv[48][256];
static size_t g_argv_count;
static char pinned_id[64];
static char identity_arn[256];
static int identity_fail;
static int g_describe_calls;

static int fake_describe(ec2_client *client, const ec2_filter *filters,
                         size_t filter_count, ec2_instance_list *out) {
    (void)client;
    (void)filters;
    (void)filter_count;
    g_describe_calls++;
    out->count = fixture_count;
    out->items = NULL;
    if (fixture_count > 0) {
        out->items = calloc(fixture_count, sizeof(ec2_instance));
        if (out->items == NULL) {
            return ENOMEM;
        }
        memcpy(out->items, fixtures, fixture_count * sizeof(ec2_instance));
    }
    return 0;
}

static int fake_console(ec2_client *client, const char *instance_id,
                        char **output) {
    (void)client;
    (void)instance_id;
    if (!g_console_present) {
        *output = NULL;
        return 0;
    }
    *output = strdup(g_console);
    return *output != NULL ? 0 : ENOMEM;
}

static int fake_keyscan(const char *ip, int port, char **line) {
    (void)ip;
    (void)port;
    if (g_keyscan_null) {
        *line = NULL;
        return 0;
    }
    *line = strdup(g_key_line);
    return *line != NULL ? 0 : ENOMEM;
}

static int fake_identity(aws_ctx *ctx, char **account, char **arn,
                         char **user_id) {
    (void)ctx;
    if (account != NULL) {
        *account = NULL;
    }
    if (user_id != NULL) {
        *user_id = NULL;
    }
    if (identity_fail) {
        return EIO;
    }
    *arn = strdup(identity_arn);
    return *arn != NULL ? 0 : ENOMEM;
}

static bool fake_kh_bound(const char *store, const char *id) {
    (void)store;
    (void)id;
    return g_bound != 0;
}

static int fake_kh_pin(const char *store, const char *id, const char *line) {
    (void)store;
    (void)line;
    snprintf(pinned_id, sizeof pinned_id, "%s", id);
    return 0;
}

static int fake_ssh(char *const argv[], int timeout,
                    const sshc_sentinel_spec *sentinel, int *remote_rc) {
    (void)timeout;
    (void)sentinel;
    g_argv_count = 0;
    for (size_t i = 0; argv[i] != NULL && i < 48; i++) {
        snprintf(g_argv[i], sizeof g_argv[i], "%s", argv[i]);
        g_argv_count++;
    }
    if (g_ssh_fail) {
        return ENOTCONN;
    }
    *remote_rc = g_remote_rc;
    return 0;
}

/* --- harness ------------------------------------------------------------- */

static void reset_all(void) {
    memset(fixtures, 0, sizeof fixtures);
    fixture_count = 0;
    g_bound = 0;
    memset(g_key_line, 0, sizeof g_key_line);
    memset(g_console, 0, sizeof g_console);
    g_console_present = 0;
    g_keyscan_null = 0;
    g_ssh_fail = 0;
    g_remote_rc = 0;
    memset(g_argv, 0, sizeof g_argv);
    g_argv_count = 0;
    memset(pinned_id, 0, sizeof pinned_id);
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/demo");
    identity_fail = 0;
    g_describe_calls = 0;
}

static void add_instance(const char *id, const char *state, const char *ip) {
    ec2_instance *item = &fixtures[fixture_count++];

    memset(item, 0, sizeof *item);
    snprintf(item->instance_id, sizeof item->instance_id, "%s", id);
    snprintf(item->state, sizeof item->state, "%s", state);
    snprintf(item->public_ip, sizeof item->public_ip, "%s", ip);
    snprintf(item->tags[0].key, sizeof item->tags[0].key, "%s", "Project");
    snprintf(item->tags[0].value, sizeof item->tags[0].value, "%s", "demo");
    snprintf(item->tags[1].key, sizeof item->tags[1].key, "%s", "Name");
    snprintf(item->tags[1].value, sizeof item->tags[1].value, "%s", "box.example.com");
    item->tag_count = 2;
}

static void make_runtime(instance_runtime *rt, instance_services *svc) {
    instance_config cfg;

    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.project, sizeof cfg.project, "%s", "demo");
    snprintf(cfg.region, sizeof cfg.region, "%s", "us-east-1");
    snprintf(cfg.key_name, sizeof cfg.key_name, "%s", "demo-key");
    snprintf(cfg.ssh_identity, sizeof cfg.ssh_identity, "%s", "/tmp/id");
    snprintf(cfg.ssh_user, sizeof cfg.ssh_user, "%s", "ec2-user");
    cfg.ssh_port = 22;
    snprintf(cfg.service_unit, sizeof cfg.service_unit, "%s", "demo.service");
    snprintf(cfg.operator_cidr, sizeof cfg.operator_cidr, "%s", "203.0.113.0/24");

    memset(svc, 0, sizeof *svc);
    svc->ec2_describe_instances = fake_describe;
    svc->ec2_get_console_output = fake_console;
    svc->keyscan = fake_keyscan;
    svc->kh_bound = fake_kh_bound;
    svc->kh_pin = fake_kh_pin;
    svc->ssh_exec = fake_ssh;
    svc->iam_get_caller_identity = fake_identity;

    instance_runtime_init(rt, &cfg, NULL, svc, 0, 0, 0);
    rt->out = tmpfile();
    rt->err = tmpfile();
}

static void free_runtime(instance_runtime *rt) {
    if (rt->out != NULL) {
        fclose(rt->out);
    }
    if (rt->err != NULL) {
        fclose(rt->err);
    }
}

static int argv_has(const char *needle) {
    for (size_t i = 0; i < g_argv_count; i++) {
        if (strstr(g_argv[i], needle) != NULL) {
            return 1;
        }
    }
    return 0;
}

static void configure_matching_console(void) {
    char fingerprint[INST_FINGERPRINT_MAX];

    snprintf(g_key_line, sizeof g_key_line,
             "203.0.113.9 ssh-ed25519 "
             "AAAAC3NzaC1lZDI1NTE5AAAAIJ8Lk7v5H0m0b2w7p8eQ0f3o5w5m6v8j3h9r2s1t4u6v");
    instance_key_fingerprint(g_key_line, fingerprint, sizeof fingerprint);
    snprintf(g_console, sizeof g_console,
             "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
             "256 %s root (ED25519)\n"
             "-----END SSH HOST KEY FINGERPRINTS-----\n",
             fingerprint);
    g_console_present = 1;
}

/* --- tests --------------------------------------------------------------- */

static void test_start_bound(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 1;

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_OK, "bound start exits 0");
    CHECK(argv_has("HostKeyAlias=i-1") || argv_has("i-1"),
          "ssh argv carries HostKeyAlias/instance id");
    CHECK(argv_has("systemctl") && argv_has("start") &&
              argv_has("demo.service"),
          "ssh argv runs systemctl start <unit>");
    free_runtime(&rt);
}

static void test_stop_command(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 1;

    rc = startstop_execute(&rt, &opts, STARTSTOP_STOP);

    CHECK(rc == CLI_EXIT_OK, "bound stop exits 0");
    CHECK(argv_has("stop"), "ssh argv runs systemctl stop");
    free_runtime(&rt);
}

static void test_zero_running_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "stopped", "203.0.113.9");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_USAGE, "zero running instances is exit 1");
    free_runtime(&rt);
}

static void test_two_running_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    add_instance("i-2", "running", "203.0.113.10");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_USAGE, "two running instances is exit 1");
    free_runtime(&rt);
}

static void test_missing_service_unit_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(rt.cfg.service_unit, sizeof rt.cfg.service_unit, "%s", "");
    add_instance("i-1", "running", "203.0.113.9");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_USAGE, "missing SERVICE_UNIT is exit 1");
    free_runtime(&rt);
}

static void test_empty_operator_cidr_is_exit1_without_aws(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(rt.cfg.operator_cidr, sizeof rt.cfg.operator_cidr, "%s", "");
    add_instance("i-1", "running", "203.0.113.9");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_USAGE, "empty OPERATOR_CIDR is exit 1");
    CHECK(g_describe_calls == 0,
          "no AWS call when SSH is impossible (empty OPERATOR_CIDR)");
    free_runtime(&rt);
}

static void test_unbound_reverifies_and_pins(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    configure_matching_console();

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_OK, "matching console re-verification succeeds");
    CHECK(strcmp(pinned_id, "i-1") == 0, "host key pinned after a match");
    free_runtime(&rt);
}

static void test_unbound_no_console_without_flag_is_exit7(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 0;
    g_console_present = 0;
    snprintf(g_key_line, sizeof g_key_line, "203.0.113.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_SSH, "no binding and no console is exit 7");
    CHECK(g_argv_count == 0, "no ssh attempted");
    free_runtime(&rt);
}

static void test_unbound_topu_flag_pins(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {.instance_id = NULL, .trust_new_host_key = 1};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    snprintf(g_key_line, sizeof g_key_line,
             "203.0.113.9 ssh-ed25519 "
             "AAAAC3NzaC1lZDI1NTE5AAAAIJ8Lk7v5H0m0b2w7p8eQ0f3o5w5m6v8j3h9r2s1t4u6v");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_OK, "--trust-new-host-key TOFU succeeds");
    CHECK(strcmp(pinned_id, "i-1") == 0, "TOFU pinned the scanned key");
    free_runtime(&rt);
}

static void test_ssh_transport_failure_is_exit7(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 1;
    g_ssh_fail = 1;

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_SSH, "SSH transport failure is exit 7");
    free_runtime(&rt);
}

static void test_remote_failure_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 1;
    g_remote_rc = 3;

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_USAGE, "remote systemctl non-zero is exit 1");
    free_runtime(&rt);
}

static void test_explicit_id_must_be_tagged(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {.instance_id = "i-404"};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_USAGE, "unknown explicit instance is exit 1");
    free_runtime(&rt);
}


static void test_identity_mismatch_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 1;
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/other-project");

    rc = startstop_execute(&rt, &opts, STARTSTOP_START);

    CHECK(rc == CLI_EXIT_VERIFY, "identity mismatch is exit 3");
    CHECK(g_argv_count == 0, "no systemctl ssh after an identity mismatch");
    free_runtime(&rt);
}

static void test_identity_api_error_is_exit2(void) {
    instance_runtime rt;
    instance_services svc;
    startstop_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "203.0.113.9");
    g_bound = 1;
    identity_fail = 1;

    rc = startstop_execute(&rt, &opts, STARTSTOP_STOP);

    CHECK(rc == CLI_EXIT_AWS, "identity API error is exit 2");
    CHECK(g_argv_count == 0, "no systemctl ssh when identity is unverifiable");
    free_runtime(&rt);
}

int main(void) {
    test_start_bound();
    test_stop_command();
    test_zero_running_is_exit1();
    test_two_running_is_exit1();
    test_missing_service_unit_is_exit1();
    test_empty_operator_cidr_is_exit1_without_aws();
    test_unbound_reverifies_and_pins();
    test_unbound_no_console_without_flag_is_exit7();
    test_unbound_topu_flag_pins();
    test_ssh_transport_failure_is_exit7();
    test_remote_failure_is_exit1();
    test_explicit_id_must_be_tagged();
    test_identity_mismatch_is_exit3();
    test_identity_api_error_is_exit2();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all startstop tests passed\n");
    return 0;
}
