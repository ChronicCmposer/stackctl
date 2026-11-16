/*
 * terminate_test.c — orchestration tests for `stackctl terminate` driven by an
 * injected services vtable. No network, no AWS, no DDNS. Covers argv, exit
 * codes, orchestration order, idempotency, safety refusals and failure paths.
 */

#include "terminate_internal.h"

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

/* --- fake state ---------------------------------------------------------- */

static char calls[64][24];
static size_t call_count;

static void reset_calls(void) {
    memset(calls, 0, sizeof calls);
    call_count = 0;
}

static void log_call(const char *name) {
    if (call_count < 64) {
        snprintf(calls[call_count], sizeof calls[call_count], "%s", name);
        call_count++;
    }
}

static int called(const char *name) {
    for (size_t i = 0; i < call_count; i++) {
        if (strcmp(calls[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int call_index(const char *name) {
    for (size_t i = 0; i < call_count; i++) {
        if (strcmp(calls[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* --- fake services ------------------------------------------------------- */

static ec2_instance fixtures[8];
static size_t fixture_count;
static char identity_arn[256];
static int identity_fail;

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

static int fake_describe(ec2_client *client, const ec2_filter *filters,
                         size_t filter_count, ec2_instance_list *out) {
    (void)client;
    (void)filters;
    (void)filter_count;
    log_call("describe");
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

static int terminate_fail;
static char terminated_ids[8][24];
static size_t terminated_count;

static int fake_terminate(ec2_client *client, const char *const *ids,
                          size_t id_count, ec2_terminate_result *out) {
    (void)client;
    log_call("terminate");
    if (terminate_fail) {
        return EC2_ERR_AWS_API;
    }
    out->count = id_count;
    out->items = calloc(id_count, sizeof(ec2_terminate_entry));
    if (out->items == NULL) {
        return ENOMEM;
    }
    for (size_t i = 0; i < id_count; i++) {
        snprintf(out->items[i].instance_id, sizeof out->items[i].instance_id,
                 "%s", ids[i]);
        snprintf(out->items[i].state, sizeof out->items[i].state, "%s",
                 "shutting-down");
        snprintf(terminated_ids[i], sizeof terminated_ids[i], "%s", ids[i]);
    }
    terminated_count = id_count;
    return 0;
}

static int wait_fail;
static int wait_timeout;
static int wait_calls;

static int fake_wait_terminated(ec2_client *client, const char *const *ids,
                                size_t id_count, int attempts, int interval,
                                int *timed_out) {
    (void)client;
    (void)ids;
    (void)id_count;
    (void)attempts;
    (void)interval;
    log_call("wait_terminated");
    wait_calls++;
    if (wait_fail) {
        return EC2_ERR_AWS_API;
    }
    *timed_out = wait_timeout;
    return 0;
}

static char dns_ip[64];
static int dns_fail;
static int dns_calls;

static int fake_dns(const char *domain, const char *host, char *ip,
                    bool *parked) {
    (void)domain;
    (void)host;
    log_call("dns_a_record");
    dns_calls++;
    if (dns_fail) {
        return EIO;
    }
    if (dns_ip[0] == '\0') {
        return ENOENT;
    }
    snprintf(ip, 64, "%s", dns_ip);
    if (parked != NULL) {
        *parked = strcmp(dns_ip, "0.0.0.0") == 0 ||
                  strcmp(dns_ip, "127.0.0.1") == 0;
    }
    return 0;
}

static int ddns_fail;
static int ddns_no_propagate;
static char ddns_last_ip[64];
static int ddns_calls;

static int fake_ddns(const char *host, const char *domain, const char *password,
                     const char *ip, bool *updated) {
    (void)host;
    (void)domain;
    (void)password;
    log_call("ddns_update");
    ddns_calls++;
    snprintf(ddns_last_ip, sizeof ddns_last_ip, "%s", ip);
    if (ddns_fail) {
        return EIO;
    }
    if (!ddns_no_propagate) {
        snprintf(dns_ip, sizeof dns_ip, "%s", ip);
    }
    *updated = true;
    return 0;
}

static int ssm_fail;
static char password_value[64] = "ddns-secret";

static int fake_ssm(ssm_client *client, const char *name, int decrypt,
                    ssm_parameter *out) {
    (void)client;
    (void)decrypt;
    log_call("ssm_get_parameter");
    if (ssm_fail) {
        return ENOENT;
    }
    memset(out, 0, sizeof *out);
    out->name = strdup(name);
    out->value = strdup(password_value);
    return out->name != NULL && out->value != NULL ? 0 : ENOMEM;
}

static char forgot_ids[8][24];
static size_t forgot_count;

static int fake_kh_forget(const char *store, const char *instance_id) {
    (void)store;
    log_call("kh_forget");
    if (forgot_count < 8) {
        snprintf(forgot_ids[forgot_count], sizeof forgot_ids[0], "%s",
                 instance_id);
        forgot_count++;
    }
    return 0;
}

/* --- harness ------------------------------------------------------------- */

static void reset_all(void) {
    reset_calls();
    memset(fixtures, 0, sizeof fixtures);
    fixture_count = 0;
    terminate_fail = 0;
    memset(terminated_ids, 0, sizeof terminated_ids);
    terminated_count = 0;
    wait_fail = 0;
    wait_timeout = 0;
    wait_calls = 0;
    memset(dns_ip, 0, sizeof dns_ip);
    dns_fail = 0;
    dns_calls = 0;
    ddns_fail = 0;
    ddns_no_propagate = 0;
    memset(ddns_last_ip, 0, sizeof ddns_last_ip);
    ddns_calls = 0;
    ssm_fail = 0;
    memset(forgot_ids, 0, sizeof forgot_ids);
    forgot_count = 0;
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/demo");
    identity_fail = 0;
}

static void add_instance(const char *id, const char *state, const char *ip) {
    ec2_instance *item = &fixtures[fixture_count++];

    memset(item, 0, sizeof *item);
    snprintf(item->instance_id, sizeof item->instance_id, "%s", id);
    snprintf(item->state, sizeof item->state, "%s", state);
    snprintf(item->public_ip, sizeof item->public_ip, "%s", ip);
    snprintf(item->tags[0].key, sizeof item->tags[0].key, "%s", "Project");
    snprintf(item->tags[0].value, sizeof item->tags[0].value, "%s", "demo");
    item->tag_count = 1;
}

static void make_runtime(instance_runtime *rt, instance_services *svc) {
    instance_config cfg;

    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.project, sizeof cfg.project, "%s", "demo");
    snprintf(cfg.region, sizeof cfg.region, "%s", "us-east-1");
    snprintf(cfg.ddns_host, sizeof cfg.ddns_host, "%s", "box");
    snprintf(cfg.ddns_domain, sizeof cfg.ddns_domain, "%s", "example.com");

    memset(svc, 0, sizeof *svc);
    svc->ec2_describe_instances = fake_describe;
    svc->ec2_terminate_instances = fake_terminate;
    svc->ec2_wait_terminated = fake_wait_terminated;
    svc->dns_a_record = fake_dns;
    svc->ddns_update = fake_ddns;
    svc->ssm_get_parameter = fake_ssm;
    svc->kh_forget = fake_kh_forget;
    svc->iam_get_caller_identity = fake_identity;

    instance_runtime_init(rt, &cfg, NULL, svc, 0, 0, 0);
    rt->dns_attempts = 2;
    rt->dns_interval = 0;
    rt->wait_attempts = 2;
    rt->wait_interval = 0;
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

static int stream_contains(FILE *stream, const char *needle) {
    char buffer[8192];
    size_t got;

    if (stream == NULL) {
        return 0;
    }
    fflush(stream);
    rewind(stream);
    got = fread(buffer, 1, sizeof buffer - 1, stream);
    buffer[got] = '\0';
    clearerr(stream);
    return strstr(buffer, needle) != NULL;
}

/* --- tests --------------------------------------------------------------- */

static void test_argv(void) {
    char *argv[] = {(char *)"terminate", (char *)"--instance-id", (char *)"i-9"};
    char *bad[] = {(char *)"terminate", (char *)"--bogus"};
    cli_args args;

    CHECK(cli_args_parse(3, argv, terminate_option_specs,
                         terminate_option_count, &args) == 0,
          "argv parse succeeds");
    CHECK(cli_args_value(&args, "instance-id") != NULL &&
              strcmp(cli_args_value(&args, "instance-id"), "i-9") == 0,
          "instance-id captured");
    cli_args_free(&args);

    CHECK(cli_args_parse(2, bad, terminate_option_specs,
                         terminate_option_count, &args) == EINVAL,
          "unknown option rejected");
    cli_args_free(&args);
}

static void test_single_instance_parks_when_record_matches(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = "i-1"};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.7");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.7");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "single instance terminate exits 0");
    CHECK(terminated_count == 1 && strcmp(terminated_ids[0], "i-1") == 0,
          "terminated exactly i-1");
    CHECK(call_index("describe") < call_index("terminate"),
          "described before terminating");
    CHECK(call_index("terminate") < call_index("wait_terminated"),
          "terminated before waiting");
    CHECK(ddns_calls == 1 && strcmp(ddns_last_ip, "0.0.0.0") == 0,
          "record parked at 0.0.0.0");
    CHECK(forgot_count == 1 && strcmp(forgot_ids[0], "i-1") == 0,
          "known-hosts binding forgotten");
    free_runtime(&rt);
}

static void test_single_instance_not_project_tagged(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = "i-404"};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.7");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "unknown/untagged instance is exit 1");
    CHECK(!called("terminate"), "no termination attempted");
    free_runtime(&rt);
}

static void test_single_instance_already_terminated_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = "i-1"};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "terminated", "");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE,
          "terminated target is rejected before any terminate call");
    CHECK(!called("terminate"), "no termination attempted");
    free_runtime(&rt);
}

static void test_sweep_zero_matches_still_parks(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(dns_ip, sizeof dns_ip, "%s", "203.0.113.9");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "zero-match sweep exits 0");
    CHECK(!called("terminate"), "no terminate call for zero matches");
    CHECK(ddns_calls == 1 && strcmp(ddns_last_ip, "0.0.0.0") == 0,
          "zero-match sweep still parks the record");
    free_runtime(&rt);
}

static void test_sweep_only_active_states(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    add_instance("i-2", "stopping", "198.51.100.2");
    add_instance("i-3", "terminated", "");
    add_instance("i-4", "shutting-down", "198.51.100.4");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.1");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "sweep exits 0");
    CHECK(terminated_count == 3, "three active/shutting-down instances terminated");
    CHECK(terminated_count == 3 && strcmp(terminated_ids[0], "i-1") == 0 &&
              strcmp(terminated_ids[1], "i-2") == 0 &&
              strcmp(terminated_ids[2], "i-4") == 0,
          "terminated the right ids");
    CHECK(forgot_count == 3, "all swept bindings forgotten");
    free_runtime(&rt);
}

static void test_wait_timeout_still_parks_and_forgets(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    wait_timeout = 1;

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_CLEANUP, "waiter timeout is exit 5");
    CHECK(ddns_calls == 1 && strcmp(ddns_last_ip, "0.0.0.0") == 0,
          "DNS park still runs on waiter timeout");
    CHECK(forgot_count == 1 && strcmp(forgot_ids[0], "i-1") == 0,
          "bindings still forgotten on waiter timeout");
    CHECK(stream_contains(rt.err, "waiting for termination"),
          "waiter progress is announced on stderr");
    free_runtime(&rt);
}

static void test_wait_error_still_parks_and_forgets(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    wait_fail = 1;

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_CLEANUP, "waiter API failure is exit 5");
    CHECK(ddns_calls == 1 && strcmp(ddns_last_ip, "0.0.0.0") == 0,
          "DNS park still runs when the waiter errors");
    CHECK(forgot_count == 1, "bindings still forgotten when the waiter errors");
    CHECK(stream_contains(rt.err, "failed while waiting for termination"),
          "waiter failure is reported");
    free_runtime(&rt);
}

static void test_wait_budget_is_600_seconds(void) {
    CHECK(TERMINATE_WAIT_BUDGET_SEC == 600,
          "termination waiter budget is 600 seconds");
    CHECK(terminate_wait_attempts(5) == 120,
          "600s at a 5s interval is 120 polls");
    CHECK(terminate_wait_attempts(0) == 600,
          "zero interval (test seam) is one second per poll");
    CHECK(terminate_wait_attempts(700) == 1,
          "an interval longer than the budget still polls at least once");
}

static void test_park_failure_is_exit5(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    ddns_fail = 1;

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_CLEANUP, "DDNS park failure is exit 5");
    free_runtime(&rt);
}

static void test_dns_verify_failure_is_exit5(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.1"); /* never propagates */
    ddns_no_propagate = 1;

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_CLEANUP, "DNS verification timeout is exit 5");
    free_runtime(&rt);
}

static void test_single_instance_record_elsewhere_is_not_parked(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = "i-1"};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.7");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.99");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "record pointing elsewhere still exits 0");
    CHECK(ddns_calls == 0, "record not parked when it points elsewhere");
    CHECK(forgot_count == 1, "binding still forgotten");
    free_runtime(&rt);
}

static void test_terminate_api_error(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    terminate_fail = 1;

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_AWS, "AWS terminate error is exit 2");
    free_runtime(&rt);
}


static void test_identity_mismatch_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/other-project");

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "identity mismatch is exit 3");
    CHECK(!called("terminate"), "no termination after an identity mismatch");
    free_runtime(&rt);
}

static void test_identity_api_error_is_exit2(void) {
    instance_runtime rt;
    instance_services svc;
    terminate_options opts = {.instance_id = NULL};
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-1", "running", "198.51.100.1");
    identity_fail = 1;

    rc = terminate_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_AWS, "identity API error is exit 2");
    CHECK(!called("terminate"), "no termination when identity is unverifiable");
    free_runtime(&rt);
}

int main(void) {
    test_argv();
    test_single_instance_parks_when_record_matches();
    test_single_instance_not_project_tagged();
    test_single_instance_already_terminated_is_exit1();
    test_sweep_zero_matches_still_parks();
    test_sweep_only_active_states();
    test_wait_timeout_still_parks_and_forgets();
    test_wait_error_still_parks_and_forgets();
    test_wait_budget_is_600_seconds();
    test_park_failure_is_exit5();
    test_dns_verify_failure_is_exit5();
    test_single_instance_record_elsewhere_is_not_parked();
    test_terminate_api_error();
    test_identity_mismatch_is_exit3();
    test_identity_api_error_is_exit2();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all terminate tests passed\n");
    return 0;
}
