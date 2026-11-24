/*
 * launch_test.c — orchestration tests for `stackctl launch` with an injected
 * services vtable. Covers preflight refusals, tag/spot invariants, ordering,
 * replacement, idempotency nonce and failure-path cleanup mapping.
 */

#include "launch_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SHA_A                                                                  \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SHA_B                                                                  \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SHA_C                                                                  \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

#define DEFAULT_MANIFEST                                                       \
    SHA_A "  app-deployment-go-amd64.tar\n"                                    \
          SHA_B "  app-deployment-go-arm64.tar\n"

#define TWO_AMD64_MANIFEST                                                     \
    SHA_A "  app-deployment-go-amd64.tar\n"                                    \
          SHA_C "  app-deployment-c-amd64.tar\n"

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* --- call log ------------------------------------------------------------ */

static char calls[128][24];
static size_t call_count;
static void reset_calls(void) {
    memset(calls, 0, sizeof calls);
    call_count = 0;
}
static void log_call(const char *name) {
    if (call_count < 128) {
        snprintf(calls[call_count], sizeof calls[call_count], "%s", name);
        call_count++;
    }
}
static int call_index(const char *name) {
    for (size_t i = 0; i < call_count; i++) {
        if (strcmp(calls[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}
static int called_before(const char *a, const char *b) {
    int ia = call_index(a);
    int ib = call_index(b);
    return ia >= 0 && ib >= 0 && ia < ib;
}
static int calls_named(const char *name) {
    int count = 0;

    for (size_t i = 0; i < call_count; i++) {
        if (strcmp(calls[i], name) == 0) {
            count++;
        }
    }
    return count;
}

/* --- scenario ------------------------------------------------------------ */

static ec2_instance fixtures[8];
static size_t fixture_count;
static int stack_present = 1;
static char record_ip[64];
static int record_exists = 1;
static int ssm_missing;
static int run_fail;
static int wait_timeout;
static int wait_busy_polls;
static int ddns_fail;
static int pin_fail;
static char g_console_override[1024];
static const char *g_manifest = DEFAULT_MANIFEST;
static char manifest_sha_override[65];
static int stack_has_ami = 1;
static int stack_has_arm_ami;
static char missing_ami[32];
static int terminate_timeout;
static int console_calls;
static int console_empty_calls;
static int keyscan_calls;
static int keyscan_null_calls;
static int tool_missing;
static int s3_get_calls;
static char captured_rc_path[256];
static int captured_reconnect;
static int ssh_transport_fail;
static int ssh_eintr;
static int ssh_etimedout;
static int ssh_error_code;
static int remote_rc;
static char captured_reconnect_cmd[1024];
static char last_ssh_argv[64][4096];
static size_t last_ssh_argc;
static char last_terminated[8][24];
static size_t last_terminated_count;

static char identity_arn[256];
static int identity_fail;
static char last_scp_argv[64][4096];
static size_t last_scp_argc;
static char scp_local_path[512];
static char scp_local_content[256];
static mode_t scp_local_mode;
static int scp_fail;
static int ssh_install_seen;
static int cert_bucket_enabled;

typedef struct run_capture {
    char instance_id[64];
    char instance_type[64];
    char key_name[128];
    char subnet_id[64];
    char security_group_id[64];
    char profile[128];
    char client_token[80];
    char project[64];
    char name[128];
    char nonce[80];
    char root_device[64];
    char root_type[32];
    int root_size;
    int spot;
} run_capture;
static run_capture last_run;
static int run_called;

static int fake_describe_stacks(cfn_client *client, const char *region,
                                const char *name, cfn_stack_list *out) {
    (void)client;
    (void)region;
    (void)name;
    log_call("describe_stack");
    if (!stack_present) {
        return ENOENT;
    }
    memset(out, 0, sizeof *out);
    out->items = calloc(1, sizeof(cfn_stack));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    snprintf(out->items[0].stack_name, sizeof out->items[0].stack_name, "%s",
             "demo-infra");
    out->items[0].status = CFN_STACK_STATUS_CREATE_COMPLETE;
    out->items[0].tags = calloc(2, sizeof(cfn_tag));
    out->items[0].parameters = calloc(2, sizeof(cfn_parameter));
    out->items[0].outputs = calloc(6, sizeof(cfn_output));
    if (out->items[0].tags == NULL || out->items[0].parameters == NULL ||
        out->items[0].outputs == NULL) {
        return ENOMEM;
    }
    snprintf(out->items[0].tags[1].key, sizeof out->items[0].tags[1].key, "%s",
             "stackctl:release-sha");
    {
        char digest[S3_SHA256_HEX_LEN] = {0};

        if (manifest_sha_override[0] != '\0') {
            snprintf(out->items[0].tags[1].value,
                     sizeof out->items[0].tags[1].value, "%s",
                     manifest_sha_override);
        } else {
            (void)s3_sha256_hex(g_manifest, strlen(g_manifest), digest);
            snprintf(out->items[0].tags[1].value,
                     sizeof out->items[0].tags[1].value, "%s", digest);
        }
    }
    out->items[0].tag_count = 2;
    snprintf(out->items[0].tags[0].key, sizeof out->items[0].tags[0].key, "%s",
             "stackctl:release-tag");
    snprintf(out->items[0].tags[0].value,
             sizeof out->items[0].tags[0].value, "%s", "v1.2.3");
    out->items[0].parameter_count = stack_has_ami ? 1 : 0;
    if (stack_has_ami) {
        snprintf(out->items[0].parameters[0].key,
                 sizeof out->items[0].parameters[0].key, "%s", "AmiIdAmd64");
        snprintf(out->items[0].parameters[0].value,
                 sizeof out->items[0].parameters[0].value, "%s", "ami-123");
    }
    if (stack_has_arm_ami) {
        size_t slot = out->items[0].parameter_count;

        snprintf(out->items[0].parameters[slot].key,
                 sizeof out->items[0].parameters[slot].key, "%s", "AmiIdArm64");
        snprintf(out->items[0].parameters[slot].value,
                 sizeof out->items[0].parameters[slot].value, "%s", "ami-arm");
        out->items[0].parameter_count++;
    }
    out->items[0].output_count = cert_bucket_enabled ? 6 : 5;
    snprintf(out->items[0].outputs[0].key, sizeof out->items[0].outputs[0].key,
             "%s", "SubnetId");
    snprintf(out->items[0].outputs[0].value,
             sizeof out->items[0].outputs[0].value, "%s", "subnet-1");
    snprintf(out->items[0].outputs[1].key, sizeof out->items[0].outputs[1].key,
             "%s", "SecurityGroupId");
    snprintf(out->items[0].outputs[1].value,
             sizeof out->items[0].outputs[1].value, "%s", "sg-1");
    snprintf(out->items[0].outputs[2].key, sizeof out->items[0].outputs[2].key,
             "%s", "InstanceProfileName");
    snprintf(out->items[0].outputs[2].value,
             sizeof out->items[0].outputs[2].value, "%s", "demo-instance-profile");
    snprintf(out->items[0].outputs[3].key, sizeof out->items[0].outputs[3].key,
             "%s", "ArtifactBucketName");
    snprintf(out->items[0].outputs[3].value,
             sizeof out->items[0].outputs[3].value, "%s", "demo-bucket");
    snprintf(out->items[0].outputs[4].key, sizeof out->items[0].outputs[4].key,
             "%s", "ReleaseTag");
    snprintf(out->items[0].outputs[4].value,
             sizeof out->items[0].outputs[4].value, "%s", "v1.2.3");
    if (cert_bucket_enabled) {
        snprintf(out->items[0].outputs[5].key,
                 sizeof out->items[0].outputs[5].key, "%s", "CertBucketName");
        snprintf(out->items[0].outputs[5].value,
                 sizeof out->items[0].outputs[5].value, "%s",
                 "demo-cert-bucket");
    }
    return 0;
}

static int fake_describe_instances(ec2_client *client, const ec2_filter *filters,
                                   size_t filter_count, ec2_instance_list *out) {
    (void)client;
    (void)filters;
    (void)filter_count;
    log_call("describe_instances");
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

static int fake_describe_images(ec2_client *client, const char *const *ids,
                                size_t count, ec2_image_list *out) {
    (void)client;
    memset(out, 0, sizeof *out);
    if (count > 0 && missing_ami[0] != '\0' &&
        strcmp(ids[0], missing_ami) == 0) {
        return 0;
    }
    out->items = calloc(1, sizeof(ec2_image));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    snprintf(out->items[0].image_id, sizeof out->items[0].image_id, "%s",
             count > 0 ? ids[0] : "");
    snprintf(out->items[0].root_device_name,
             sizeof out->items[0].root_device_name, "%s", "/dev/xvda");
    snprintf(out->items[0].architecture, sizeof out->items[0].architecture,
             "%s", "x86_64");
    return 0;
}

static int fake_run(ec2_client *client, const ec2_run_spec *spec,
                    ec2_run_result *out) {
    (void)client;
    log_call("run_instances");
    if (run_fail) {
        return EC2_ERR_AWS_API;
    }
    run_called = 1;
    memset(&last_run, 0, sizeof last_run);
    snprintf(last_run.instance_id, sizeof last_run.instance_id, "%s", "i-new");
    snprintf(last_run.instance_type, sizeof last_run.instance_type, "%s",
             spec->instance_type);
    snprintf(last_run.key_name, sizeof last_run.key_name, "%s", spec->key_name);
    snprintf(last_run.subnet_id, sizeof last_run.subnet_id, "%s",
             spec->subnet_id);
    snprintf(last_run.security_group_id, sizeof last_run.security_group_id,
             "%s", spec->security_group_id);
    snprintf(last_run.profile, sizeof last_run.profile, "%s",
             spec->instance_profile_name);
    snprintf(last_run.client_token, sizeof last_run.client_token, "%s",
             spec->client_token);
    snprintf(last_run.project, sizeof last_run.project, "%s", spec->project);
    snprintf(last_run.name, sizeof last_run.name, "%s", spec->name);
    snprintf(last_run.nonce, sizeof last_run.nonce, "%s", spec->launch_nonce);
    snprintf(last_run.root_device, sizeof last_run.root_device, "%s",
             spec->root_device_name);
    snprintf(last_run.root_type, sizeof last_run.root_type, "%s",
             spec->root_volume_type != NULL ? spec->root_volume_type : "");
    last_run.root_size = spec->root_volume_size_gb;
    last_run.spot = spec->spot;
    snprintf(out->instance_id, sizeof out->instance_id, "%s", "i-new");
    snprintf(out->public_ip, sizeof out->public_ip, "%s", "198.51.100.50");
    return 0;
}

static int fake_wait_running(ec2_client *client, const char *instance_id,
                             int attempts, int interval, ec2_instance *out,
                             int *timed_out) {
    (void)client;
    (void)instance_id;
    (void)attempts;
    (void)interval;
    log_call("wait_running");
    memset(out, 0, sizeof *out);
    if (wait_busy_polls > 0) {
        wait_busy_polls--;
        *timed_out = 1;
        return 0;
    }
    *timed_out = wait_timeout;
    snprintf(out->instance_id, sizeof out->instance_id, "%s", "i-new");
    snprintf(out->state, sizeof out->state, "%s", "running");
    snprintf(out->public_ip, sizeof out->public_ip, "%s", "198.51.100.50");
    return 0;
}

static int fake_terminate(ec2_client *client, const char *const *ids,
                          size_t id_count, ec2_terminate_result *out) {
    (void)client;
    log_call("terminate_instances");
    last_terminated_count = 0;
    for (size_t i = 0; i < id_count && i < 8; i++) {
        snprintf(last_terminated[i], sizeof last_terminated[i], "%s", ids[i]);
        last_terminated_count++;
    }
    out->items = calloc(id_count, sizeof(ec2_terminate_entry));
    out->count = id_count;
    return out->items != NULL ? 0 : ENOMEM;
}

static int fake_wait_terminated(ec2_client *client, const char *const *ids,
                                size_t id_count, int attempts, int interval,
                                int *timed_out) {
    (void)client;
    (void)ids;
    (void)id_count;
    (void)attempts;
    (void)interval;
    log_call("wait_terminated");
    *timed_out = terminate_timeout;
    return 0;
}

static int fake_s3_get(s3_client *client, const char *bucket, const char *key,
                       char **data_out, size_t *len_out) {
    (void)client;
    (void)bucket;
    (void)key;
    log_call("s3_get_object");
    s3_get_calls++;
    *data_out = strdup(g_manifest);
    if (*data_out == NULL) {
        return ENOMEM;
    }
    *len_out = strlen(g_manifest);
    return 0;
}

static int fake_console(ec2_client *client, const char *instance_id,
                        char **output) {
    (void)client;
    (void)instance_id;
    char line[512];
    char fingerprint[INST_FINGERPRINT_MAX];
    char buffer[1024];

    log_call("console");
    console_calls++;
    if (console_calls <= console_empty_calls) {
        *output = strdup("");
        return *output != NULL ? 0 : ENOMEM;
    }
    if (g_console_override[0] != '\0') {
        *output = strdup(g_console_override);
        return *output != NULL ? 0 : ENOMEM;
    }
    snprintf(line, sizeof line,
             "198.51.100.50 ssh-ed25519 "
             "AAAAC3NzaC1lZDI1NTE5AAAAIJ8Lk7v5H0m0b2w7p8eQ0f3o5w5m6v8j3h9r2s1t4u6v");
    instance_key_fingerprint(line, fingerprint, sizeof fingerprint);
    snprintf(buffer, sizeof buffer,
             "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
             "256 %s root (ED25519)\n"
             "-----END SSH HOST KEY FINGERPRINTS-----\n",
             fingerprint);
    *output = strdup(buffer);
    return *output != NULL ? 0 : ENOMEM;
}

static int fake_keyscan(const char *ip, int port, char **line) {
    (void)ip;
    (void)port;
    log_call("keyscan");
    keyscan_calls++;
    if (keyscan_calls <= keyscan_null_calls) {
        *line = NULL;
        return 0;
    }
    *line = strdup(
        "198.51.100.50 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIJ8Lk7v5H0m0b2w7p8eQ0f3o5w5m6v8j3h9r2s1t4u6v");
    return *line != NULL ? 0 : ENOMEM;
}

static int fake_tool_available(const char *name) {
    (void)name;
    return tool_missing ? 0 : 1;
}

static int fake_pin(const char *store, const char *id, const char *line) {
    (void)store;
    (void)id;
    (void)line;
    log_call("kh_pin");
    return pin_fail;
}

static int fake_ssh(char *const argv[], int timeout,
                    const sshc_sentinel_spec *sentinel, int *remote_status) {
    (void)timeout;
    log_call("ssh_exec");
    if (sentinel != NULL) {
        snprintf(captured_rc_path, sizeof captured_rc_path, "%s",
                 sentinel->remote_rc_path != NULL ? sentinel->remote_rc_path
                                                  : "");
        captured_reconnect = sentinel->reconnect_argv != NULL &&
                             sentinel->reconnect_argv[0] != NULL;
        captured_reconnect_cmd[0] = '\0';
        if (sentinel->reconnect_argv != NULL) {
            for (size_t i = 0; sentinel->reconnect_argv[i] != NULL && i < 64;
                 i++) {
                snprintf(captured_reconnect_cmd,
                         sizeof captured_reconnect_cmd, "%s",
                         sentinel->reconnect_argv[i]);
            }
        }
    }
    last_ssh_argc = 0;
    for (size_t i = 0; argv[i] != NULL && i < 64; i++) {
        snprintf(last_ssh_argv[i], sizeof last_ssh_argv[i], "%s", argv[i]);
        last_ssh_argc++;
        if (strstr(argv[i], "install -D") != NULL) {
            ssh_install_seen = 1;
        }
    }
    if (ssh_eintr) {
        return EINTR;
    }
    if (ssh_etimedout) {
        return ETIMEDOUT;
    }
    if (ssh_transport_fail) {
        return ENOTCONN;
    }
    if (ssh_error_code != 0) {
        return ssh_error_code;
    }
    *remote_status = remote_rc;
    return 0;
}

static int fake_scp(char *const argv[], int timeout,
                    const sshc_sentinel_spec *sentinel, int *remote_status) {
    (void)timeout;
    (void)sentinel;
    log_call("scp_exec");
    last_scp_argc = 0;
    for (size_t i = 0; argv[i] != NULL && i < 64; i++) {
        snprintf(last_scp_argv[i], sizeof last_scp_argv[i], "%s", argv[i]);
        last_scp_argc++;
    }
    memset(scp_local_path, 0, sizeof scp_local_path);
    memset(scp_local_content, 0, sizeof scp_local_content);
    if (last_scp_argc >= 2) {
        FILE *file;

        snprintf(scp_local_path, sizeof scp_local_path, "%s",
                 last_scp_argv[last_scp_argc - 2]);
        struct stat info;

        if (stat(scp_local_path, &info) == 0) {
            scp_local_mode = info.st_mode;
        }
        file = fopen(scp_local_path, "r");
        if (file != NULL) {
            size_t got = fread(scp_local_content, 1,
                               sizeof scp_local_content - 1, file);

            scp_local_content[got] = '\0';
            fclose(file);
        }
    }
    if (scp_fail) {
        return ENOTCONN;
    }
    *remote_status = 0;
    return 0;
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
    log_call("iam_identity");
    if (identity_fail) {
        return EIO;
    }
    *arn = strdup(identity_arn);
    return *arn != NULL ? 0 : ENOMEM;
}

static int fake_ssm(ssm_client *client, const char *name, int decrypt,
                    ssm_parameter *out) {
    (void)client;
    (void)decrypt;
    log_call("ssm");
    if (ssm_missing) {
        return ENOENT;
    }
    memset(out, 0, sizeof *out);
    out->name = strdup(name);
    out->value = strdup("ddns-secret");
    return out->name != NULL && out->value != NULL ? 0 : ENOMEM;
}

static int fake_dns_record_exists(const char *domain, const char *host,
                                  bool *exists) {
    (void)domain;
    (void)host;
    *exists = record_exists != 0;
    return 0;
}

static int fake_dns(const char *domain, const char *host, char *ip,
                    bool *parked) {
    (void)domain;
    (void)host;
    log_call("dns_a_record");
    if (record_ip[0] == '\0') {
        return ENOENT;
    }
    snprintf(ip, 64, "%s", record_ip);
    if (parked != NULL) {
        *parked = strcmp(record_ip, "0.0.0.0") == 0;
    }
    return 0;
}

static int fake_ddns(const char *host, const char *domain, const char *password,
                     const char *ip, bool *updated) {
    (void)host;
    (void)domain;
    (void)password;
    log_call("ddns_update");
    if (ddns_fail) {
        return EIO;
    }
    snprintf(record_ip, sizeof record_ip, "%s", ip);
    *updated = true;
    return 0;
}

/* --- harness ------------------------------------------------------------- */

static void reset_all(void) {
    reset_calls();
    memset(fixtures, 0, sizeof fixtures);
    fixture_count = 0;
    stack_present = 1;
    memset(record_ip, 0, sizeof record_ip);
    record_exists = 1;
    ssm_missing = 0;
    run_fail = 0;
    wait_timeout = 0;
    wait_busy_polls = 0;
    ddns_fail = 0;
    pin_fail = 0;
    ssh_transport_fail = 0;
    ssh_eintr = 0;
    ssh_etimedout = 0;
    ssh_error_code = 0;
    remote_rc = 0;
    captured_reconnect_cmd[0] = '\0';
    memset(last_ssh_argv, 0, sizeof last_ssh_argv);
    last_ssh_argc = 0;
    memset(last_terminated, 0, sizeof last_terminated);
    last_terminated_count = 0;
    memset(&last_run, 0, sizeof last_run);
    memset(g_console_override, 0, sizeof g_console_override);
    g_manifest = DEFAULT_MANIFEST;
    memset(manifest_sha_override, 0, sizeof manifest_sha_override);
    stack_has_ami = 1;
    stack_has_arm_ami = 0;
    missing_ami[0] = '\0';
    terminate_timeout = 0;
    console_calls = 0;
    console_empty_calls = 0;
    keyscan_calls = 0;
    keyscan_null_calls = 0;
    tool_missing = 0;
    s3_get_calls = 0;
    memset(captured_rc_path, 0, sizeof captured_rc_path);
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/demo");
    identity_fail = 0;
    memset(last_scp_argv, 0, sizeof last_scp_argv);
    last_scp_argc = 0;
    memset(scp_local_path, 0, sizeof scp_local_path);
    memset(scp_local_content, 0, sizeof scp_local_content);
    scp_local_mode = 0;
    scp_fail = 0;
    ssh_install_seen = 0;
    cert_bucket_enabled = 0;
    captured_reconnect = 0;
    run_called = 0;
}

static void add_instance(const char *id, const char *state, const char *ip,
                         const char *nonce) {
    ec2_instance *item = &fixtures[fixture_count++];

    memset(item, 0, sizeof *item);
    snprintf(item->instance_id, sizeof item->instance_id, "%s", id);
    snprintf(item->state, sizeof item->state, "%s", state);
    snprintf(item->public_ip, sizeof item->public_ip, "%s", ip);
    snprintf(item->tags[0].key, sizeof item->tags[0].key, "%s", "Project");
    snprintf(item->tags[0].value, sizeof item->tags[0].value, "%s", "demo");
    snprintf(item->tags[1].key, sizeof item->tags[1].key, "%s",
             "stackctl:launch-nonce");
    snprintf(item->tags[1].value, sizeof item->tags[1].value, "%s",
             nonce != NULL ? nonce : "old-nonce");
    item->tag_count = 2;
}

static void make_runtime(instance_runtime *rt, instance_services *svc) {
    instance_config cfg;

    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.project, sizeof cfg.project, "%s", "demo");
    snprintf(cfg.region, sizeof cfg.region, "%s", "us-east-1");
    snprintf(cfg.arch, sizeof cfg.arch, "%s", "amd64");
    cfg.spot_default = 1;
    snprintf(cfg.ami_policy, sizeof cfg.ami_policy, "%s", "pinned");
    snprintf(cfg.instance_types_amd64, sizeof cfg.instance_types_amd64, "%s",
             "g4dn.xlarge,g6.xlarge");
    cfg.root_volume_size_gb = 100;
    snprintf(cfg.root_volume_type, sizeof cfg.root_volume_type, "%s", "gp3");
    snprintf(cfg.key_name, sizeof cfg.key_name, "%s", "demo-key");
    snprintf(cfg.ssh_identity, sizeof cfg.ssh_identity, "%s", "/tmp/id");
    snprintf(cfg.ssh_user, sizeof cfg.ssh_user, "%s", "ec2-user");
    cfg.ssh_port = 22;
    snprintf(cfg.operator_cidr, sizeof cfg.operator_cidr, "%s", "203.0.113.0/24");
    snprintf(cfg.setup_entrypoint, sizeof cfg.setup_entrypoint, "%s",
             "deploy.sh");
    snprintf(cfg.ddns_host, sizeof cfg.ddns_host, "%s", "box");
    snprintf(cfg.ddns_domain, sizeof cfg.ddns_domain, "%s", "example.com");
    snprintf(cfg.bucket_modules, sizeof cfg.bucket_modules, "%s", "artifact");

    memset(svc, 0, sizeof *svc);
    svc->cfn_describe_stacks = fake_describe_stacks;
    svc->ec2_describe_instances = fake_describe_instances;
    svc->ec2_describe_images = fake_describe_images;
    svc->ec2_run_instances = fake_run;
    svc->ec2_wait_running = fake_wait_running;
    svc->ec2_terminate_instances = fake_terminate;
    svc->ec2_wait_terminated = fake_wait_terminated;
    svc->ec2_get_console_output = fake_console;
    svc->keyscan = fake_keyscan;
    svc->tool_available = fake_tool_available;
    svc->kh_pin = fake_pin;
    svc->ssh_exec = fake_ssh;
    svc->scp_exec = fake_scp;
    svc->iam_get_caller_identity = fake_identity;
    svc->ssm_get_parameter = fake_ssm;
    svc->s3_get_object = fake_s3_get;
    svc->dns_record_exists = fake_dns_record_exists;
    svc->dns_a_record = fake_dns;
    svc->ddns_update = fake_ddns;

    instance_runtime_init(rt, &cfg, NULL, svc, 0, 0, 0);
    rt->dns_attempts = 2;
    rt->dns_interval = 0;
    rt->wait_attempts = 2;
    rt->wait_interval = 0;
    rt->ssh_attempts = 3;
    rt->ssh_interval = 0;
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

static launch_options default_options(void) {
    launch_options opts;

    memset(&opts, 0, sizeof opts);
    opts.spot_set = -1;
    return opts;
}

static int terminated(const char *id) {
    for (size_t i = 0; i < last_terminated_count; i++) {
        if (strcmp(last_terminated[i], id) == 0) {
            return 1;
        }
    }
    return 0;
}

static int failing_append(state_store *store, const state_launch_record *record) {
    (void)store;
    (void)record;
    return EIO;
}

static int stream_contains(FILE *stream, const char *needle) {
    char buffer[8192];
    size_t got;
    int found = 0;

    if (stream == NULL) {
        return 0;
    }
    fflush(stream);
    rewind(stream);
    got = fread(buffer, 1, sizeof buffer - 1, stream);
    buffer[got] = '\0';
    if (strstr(buffer, needle) != NULL) {
        found = 1;
    }
    clearerr(stream);
    return found;
}

/*
 * Return the byte offset of the first occurrence of `needle` in a captured
 * stream, or -1 when absent. Used to assert phase announcements appear in the
 * order the launch performs them.
 */
static long stream_position(FILE *stream, const char *needle) {
    char buffer[8192];
    size_t got;
    char *found;

    if (stream == NULL) {
        return -1;
    }
    fflush(stream);
    rewind(stream);
    got = fread(buffer, 1, sizeof buffer - 1, stream);
    buffer[got] = '\0';
    clearerr(stream);
    found = strstr(buffer, needle);
    return found != NULL ? (long)(found - buffer) : -1;
}

static int any_ssh_contains(const char *needle);

static int file_contains(const char *path, const char *needle) {
    FILE *file = fopen(path, "r");
    char line[1024];
    int found = 0;

    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof line, file) != NULL) {
        if (strstr(line, needle) != NULL) {
            found = 1;
            break;
        }
    }
    fclose(file);
    return found;
}

static state_store *open_temp_state(char *root, size_t cap) {
    state_store *store = NULL;

    snprintf(root, cap, "/tmp/stackctl-launch-state-XXXXXX");
    if (mkdtemp(root) == NULL) {
        return NULL;
    }
    setenv("XDG_STATE_HOME", root, 1);
    if (state_open("demo", "us-east-1", &store) != 0) {
        return NULL;
    }
    return store;
}

static void close_temp_state(state_store *store, const char *root) {
    char dir[600];
    char *slash;

    if (store == NULL) {
        return;
    }
    unlink(state_known_hosts_path(store));
    unlink(state_bindings_path(store));
    unlink(state_launch_records_path(store));
    unlink(state_operations_log_path(store));
    unlink(state_release_history_path(store));
    snprintf(dir, sizeof dir, "%s", state_dir(store));
    state_close(store);
    rmdir(dir);
    slash = strrchr(dir, '/');
    if (slash != NULL) {
        *slash = '\0';
        rmdir(dir);
    }
    rmdir(root);
    unsetenv("XDG_STATE_HOME");
}

/* Send a launch through with one previous instance to be replaced. */
static int run_replacement_launch(instance_runtime *rt, state_store *store) {
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    make_runtime(rt, &svc);
    rt->state = store;
    add_instance("i-old", "running", "198.51.100.7", "old-nonce");
    snprintf(record_ip, sizeof record_ip, "%s", "198.51.100.7");
    rc = launch_execute(rt, &opts);
    return rc;
}

/* --- tests --------------------------------------------------------------- */

static void test_missing_stack_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    stack_present = 0;
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing infra stack is exit 1");
    CHECK(!run_called, "no RunInstances before the stack resolves");
    free_runtime(&rt);
}

static void test_empty_operator_cidr_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(rt.cfg.operator_cidr, sizeof rt.cfg.operator_cidr, "%s", "");
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "empty OPERATOR_CIDR is exit 1");
    CHECK(!run_called, "no spend when SSH is impossible");
    free_runtime(&rt);
}

static void test_missing_keyscan_is_exit1_before_spend(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    tool_missing = 1;
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing ssh-keyscan preflight is exit 1");
    CHECK(!run_called, "no spend when ssh-keyscan is unavailable");
    CHECK(stream_contains(rt.err, "ssh-keyscan"),
          "diagnostic names the missing ssh-keyscan tool");
    free_runtime(&rt);
}

static void test_missing_ddns_record_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    record_exists = 0;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing DDNS record is exit 1");
    CHECK(!run_called, "no spend without the pre-existing record");
    free_runtime(&rt);
}

static void test_missing_ssm_param_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    ssm_missing = 1;
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing SSM DDNS parameter is exit 1");
    CHECK(!run_called, "no spend without the DDNS secret");
    free_runtime(&rt);
}

static void test_both_arch_requires_flag(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(rt.cfg.arch, sizeof rt.cfg.arch, "%s", "both");
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "ARCH=both without --arch is exit 1");
    CHECK(!run_called, "no spend without a chosen arch");
    free_runtime(&rt);
}

static void test_type_not_allowlisted_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    opts.instance_type = "m5.large";
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "non-allowlisted type is exit 1");
    CHECK(!run_called, "no spend with an invalid type");
    free_runtime(&rt);
}

static void test_happy_path_orchestration(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-old", "running", "198.51.100.7", "old-nonce");
    snprintf(record_ip, sizeof record_ip, "%s", "198.51.100.7");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "happy-path launch exits 0");
    CHECK(run_called, "RunInstances was called");
    CHECK(strcmp(last_run.project, "demo") == 0, "Project tag emitted");
    CHECK(strcmp(last_run.name, "box.example.com") == 0, "Name tag is the FQDN");
    CHECK(strlen(last_run.nonce) == 32, "launch nonce is 32 hex chars");
    CHECK(strlen(last_run.client_token) == 64, "client token is 64 hex chars");
    CHECK(strcmp(last_run.root_device, "/dev/xvda") == 0,
          "root device from the image");
    CHECK(last_run.root_size == 100, "root volume size from config");
    CHECK(last_run.spot == 1, "SPOT_DEFAULT=true -> spot launch");
    CHECK(called_before("run_instances", "wait_running"),
          "run before the ready waiter");
    CHECK(called_before("wait_running", "ddns_update"),
          "IP waiter before DDNS update");
    CHECK(called_before("ddns_update", "ssh_exec"),
          "DDNS before the setup SSH session");
    CHECK(terminated("i-old"), "the previous instance is replaced");
    free_runtime(&rt);
}

static void test_no_spot_override(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    opts.spot_set = 0;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "no-spot launch exits 0");
    CHECK(run_called && last_run.spot == 0, "--no-spot overrides the default");
    free_runtime(&rt);
}

static void test_keep_old_skips_replacement(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-old", "running", "198.51.100.7", "old-nonce");
    snprintf(record_ip, sizeof record_ip, "%s", "198.51.100.7");
    opts.keep_old = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "--keep-old launch exits 0");
    CHECK(!terminated("i-old"), "--keep-old leaves the old instance");
    free_runtime(&rt);
}

static void test_run_instances_error_is_exit2(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    run_fail = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_AWS, "RunInstances AWS error is exit 2");
    CHECK(!called_before("terminate_instances", "run_instances"),
          "nothing to terminate when RunInstances failed");
    free_runtime(&rt);
}

static void test_ssh_transport_failure_is_exit7_and_terminates(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-old", "running", "198.51.100.7", "old-nonce");
    snprintf(record_ip, sizeof record_ip, "%s", "198.51.100.7");
    ssh_transport_fail = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_SSH, "SSH transport failure is exit 7");
    CHECK(terminated("i-new"), "failed instance terminated");
    CHECK(stream_contains(rt.err, "OPERATOR_CIDR"),
          "exit-7 diagnostic carries the OPERATOR_CIDR hint");
    free_runtime(&rt);
}

static void test_ssh_error_is_exit7_with_hint(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    ssh_error_code = EIO;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_SSH, "non-connect SSH error is exit 7");
    CHECK(terminated("i-new"), "SSH error terminates the instance");
    CHECK(stream_contains(rt.err, "OPERATOR_CIDR"),
          "non-connect exit-7 diagnostic carries the hint");
    free_runtime(&rt);
}

static void test_setup_failure_is_exit4(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    remote_rc = 7;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_LAUNCH, "setup non-zero is exit 4");
    CHECK(terminated("i-new"), "failed instance terminated");
    free_runtime(&rt);
}

static void test_entrypoint_output_is_surfaced(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "launch with output surfacing exits 0");
    CHECK(last_ssh_argc > 0 &&
              strstr(last_ssh_argv[last_ssh_argc - 1], "setup.log") != NULL,
          "setup script captures entrypoint output to a log");
    CHECK(any_ssh_contains("tail -n 150") && any_ssh_contains(">&2"),
          "setup script mirrors the last 150 lines to stderr");
    free_runtime(&rt);
}

static void test_setup_script_extracts_and_reinjects_env(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    const char *script;
    const char *precheck;
    const char *extract;
    const char *entry_check;
    const char *reinject;
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    script = last_ssh_argc > 0 ? last_ssh_argv[last_ssh_argc - 1] : "";
    precheck = strstr(script, "tar -tf");
    extract = strstr(script, "tar --no-same-owner");
    entry_check = strstr(script, "SETUP_ENTRYPOINT");
    reinject = strstr(script, "(cd \"$d\" && sudo env ");
    CHECK(rc == CLI_EXIT_OK, "launch with extracted bundle exits 0");
    CHECK(precheck != NULL, "setup script prechecks tar member paths");
    CHECK(extract != NULL && strstr(extract, "--no-overwrite-dir") != NULL &&
              strstr(extract, "-xf") != NULL,
          "setup script extracts hardened (no-same-owner/no-overwrite-dir)");
    CHECK(extract != NULL && strstr(extract, "-C \"$d\"") != NULL,
          "setup script extracts into the staging dir");
    CHECK(entry_check != NULL && strstr(script, "! -x") != NULL,
          "setup script checks the entrypoint exists and is executable");
    CHECK(reinject != NULL,
          "entrypoint runs from the bundle root with re-injected env");
    CHECK(precheck != NULL && extract != NULL && reinject != NULL &&
              precheck < extract && extract < reinject,
          "precheck, extract, and run happen in order");
    CHECK(strstr(script, "STACKCTL_PROJECT=\"$STACKCTL_PROJECT\"") != NULL,
          "env re-injection references STACKCTL_PROJECT");
    CHECK(strstr(script, "STACKCTL_BUCKET_ARTIFACT=\"$STACKCTL_BUCKET_ARTIFACT\"") !=
              NULL,
          "env re-injection carries the full contract var set");
    free_runtime(&rt);
}

static void test_setup_script_failure_classes_are_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    /* A staged bundle that fails the sha/extract/entrypoint class (rc=3). */
    remote_rc = 3;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "setup rc=3 maps to exit 3");
    CHECK(terminated("i-new"), "failed instance terminated");
    /* The generated script routes the same class to rc=3. */
    CHECK(any_ssh_contains("tar -tf") &&
              any_ssh_contains("sudo tar --no-same-owner"),
          "precheck extract before entrypoint");
    CHECK(any_ssh_contains("SETUP_ENTRYPOINT"), "entrypoint check names the key");
    CHECK(any_ssh_contains("rc=3"), "bundle failures map to rc=3");
    free_runtime(&rt);
}

static void test_interrupt_exits_4_and_consumes_signal(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    cli_signal_test_reset();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    ssh_eintr = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_LAUNCH, "interrupted setup is exit 4");
    CHECK(terminated("i-new"), "interrupted launch terminates the instance");
    CHECK(cli_signal_consumed() != 0,
          "launch marks the signal consumed so dispatch honors exit 4");
    cli_signal_test_reset();
    free_runtime(&rt);
}

static void test_setup_timeout_is_exit4(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    ssh_etimedout = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_LAUNCH, "setup timeout is exit 4");
    CHECK(terminated("i-new"), "setup timeout terminates the instance");
    CHECK(calls_named("ddns_update") >= 2,
          "setup timeout restores DDNS after the ssh attempt");
    free_runtime(&rt);
}

static void test_keep_on_failure_keeps_instance(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    ssh_transport_fail = 1;
    opts.keep_on_failure = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_SSH, "--keep-on-failure still exits 7");
    CHECK(!terminated("i-new"), "--keep-on-failure leaves the new instance");
    CHECK(stream_contains(
              rt.err,
              "stackctl: check that OPERATOR_CIDR covers this machine and "
              "that the security group's SSH rule allows it\n"),
          "exit-7 keep-on-failure diagnostic carries the full retry hint");
    free_runtime(&rt);
}

static void test_hostkey_mismatch_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    snprintf(g_console_override, sizeof g_console_override,
             "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
             "256 SHA256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeed root "
             "(ED25519)\n"
             "-----END SSH HOST KEY FINGERPRINTS-----\n");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "host-key mismatch is exit 3");
    CHECK(terminated("i-new"), "mismatch terminates the instance");
    free_runtime(&rt);
}

static void test_pin_failure_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    pin_fail = EPERM;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "known-hosts pin EPERM is exit 3");
    CHECK(stream_contains(rt.err, "pinning the host key failed:"),
          "a failed pin is announced with the errno text");
    CHECK(stream_contains(rt.err, "launch failed (host-key pin failed)"),
          "the launch-failed reason names the pin step");
    CHECK(terminated("i-new"), "pin failure terminates the instance");
    free_runtime(&rt);
}

static void test_binding_write_failure_announced(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    state_store *store;
    kh_binding stale;
    char root[256];
    int rc;

    reset_all();
    store = open_temp_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }
    memset(&stale, 0, sizeof stale);
    snprintf(stale.instance_id, sizeof stale.instance_id, "%s", "i-new");
    snprintf(stale.host_key, sizeof stale.host_key, "%s",
             "SHA256:stale0000000000000000000000000000000000000000");
    snprintf(stale.fqdn, sizeof stale.fqdn, "%s", "box.example.com");
    snprintf(stale.ip, sizeof stale.ip, "%s", "198.51.100.9");
    CHECK(state_binding_put(store, &stale) == 0, "stale binding is seeded");

    make_runtime(&rt, &svc);
    rt.state = store;
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY,
          "binding conflict (same id, changed key) is exit 3");
    CHECK(stream_contains(rt.err, "recording the known-hosts binding failed"),
          "a failed binding write is announced");
    CHECK(stream_contains(rt.err, "launch failed (binding write failed)"),
          "the launch-failed reason names the binding write");
    CHECK(terminated("i-new"), "binding failure terminates the instance");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_manifest_selection_honors_variant(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    g_manifest = TWO_AMD64_MANIFEST;
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    opts.variant = "c";

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "explicit --variant launch exits 0");
    CHECK(last_ssh_argc > 0 &&
              strstr(last_ssh_argv[last_ssh_argc - 1],
                     "app-deployment-c-amd64.tar") != NULL,
          "selected c member is passed to the box");
    CHECK(last_ssh_argc > 0 &&
              strstr(last_ssh_argv[last_ssh_argc - 1],
                     "STACKCTL_VARIANT='c'") != NULL,
          "STACKCTL_VARIANT is non-empty and honours --variant");
    CHECK(called_before("s3_get_object", "run_instances"),
          "manifest is resolved before any instance spend");
    free_runtime(&rt);
}

static void test_manifest_ambiguity_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    g_manifest = TWO_AMD64_MANIFEST;
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "ambiguous member without --variant is exit 1");
    CHECK(!run_called, "no spend when the member is ambiguous");
    CHECK(stream_contains(rt.err, "app-deployment-go-amd64.tar") &&
              stream_contains(rt.err, "app-deployment-c-amd64.tar"),
          "ambiguity diagnostic names the candidate members");
    free_runtime(&rt);
}

static void test_manifest_missing_member_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    opts.variant = "zzz";

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "missing selected member is exit 3");
    CHECK(!run_called, "no spend when the member is missing");
    free_runtime(&rt);
}

static void test_manifest_sha_mismatch_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    snprintf(manifest_sha_override, sizeof manifest_sha_override, "%s", SHA_C);

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "manifest sha mismatch is exit 3");
    CHECK(!run_called, "no spend when the manifest does not verify");
    free_runtime(&rt);
}

static void test_console_polling_retries(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    console_empty_calls = 2;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "console polling converges and exits 0");
    CHECK(console_calls == 3, "console output was polled until fingerprints");
    free_runtime(&rt);
}

static void test_keyscan_retry_within_timeout(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    rt.ssh_attempts = 5;
    keyscan_null_calls = 2;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "keyscan retry converges and exits 0");
    CHECK(keyscan_calls == 3, "keyscan was retried within the timeout");
    free_runtime(&rt);
}

static void test_keyscan_timeout_is_exit7(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    rt.ssh_attempts = 2;
    keyscan_null_calls = 999;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_SSH, "keyscan timeout is exit 7");
    CHECK(keyscan_calls == 2, "keyscan polling is bounded by the timeout");
    CHECK(terminated("i-new"), "keyscan timeout terminates the instance");
    CHECK(stream_contains(rt.err, "OPERATOR_CIDR"),
          "keyscan exit-7 diagnostic carries the hint");
    free_runtime(&rt);
}

static void test_rc_path_and_reconnect_contract(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    char expected[128];
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    snprintf(expected, sizeof expected, "/run/stackctl-setup.%s/rc",
             last_run.nonce);
    CHECK(rc == CLI_EXIT_OK, "happy path still exits 0");
    CHECK(strcmp(captured_rc_path, expected) == 0,
          "sentinel carries the real remote rc path");
    CHECK(captured_reconnect, "sentinel provides the reconnect-once argv");
    CHECK(last_ssh_argc > 0 &&
              strstr(last_ssh_argv[last_ssh_argc - 1],
                     "/run/stackctl-setup.") != NULL,
          "setup command stages under /run/stackctl-setup.<nonce>");
    CHECK(last_ssh_argc > 0 &&
              strstr(last_ssh_argv[last_ssh_argc - 1], "rm -rf \"$d\"") != NULL,
          "successful setup removes the staging dir");
    free_runtime(&rt);
}

static void test_pinned_ami_has_no_config_fallback(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    stack_has_ami = 0;
    snprintf(rt.cfg.ami_id_amd64, sizeof rt.cfg.ami_id_amd64, "%s",
             "ami-from-config");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing stack AmiId is exit 1 under pinned");
    CHECK(!run_called, "config AMI is never used as a pinned fallback");
    free_runtime(&rt);
}

static void test_replaced_ids_recorded(void) {
    instance_runtime rt;
    state_store *store;
    char root[256];
    char records_path[600];
    char ops_path[600];
    int rc;

    reset_all();
    store = open_temp_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }
    rc = run_replacement_launch(&rt, store);
    snprintf(records_path, sizeof records_path, "%s",
             state_launch_records_path(store));
    snprintf(ops_path, sizeof ops_path, "%s",
             state_operations_log_path(store));

    CHECK(rc == CLI_EXIT_OK, "launch with real state exits 0");
    CHECK(file_contains(records_path, "i-old"),
          "launch record records the replaced instance id");
    CHECK(file_contains(ops_path, "i-old"),
          "operations.log records the replaced instance id");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_state_append_failure_is_cleanup(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    rt.launch_record_append = failing_append;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_CLEANUP,
          "launch-record append failure is a cleanup failure");
    CHECK(terminated("i-new"),
          "unrecorded instance is terminated so no orphan remains");
    free_runtime(&rt);
}


static int any_ssh_contains(const char *needle) {
    for (size_t i = 0; i < last_ssh_argc; i++) {
        if (strstr(last_ssh_argv[i], needle) != NULL) {
            return 1;
        }
    }
    return 0;
}

static void test_identity_mismatch_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/other-project");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "identity mismatch is exit 3");
    CHECK(!run_called, "no RunInstances after an identity mismatch");
    free_runtime(&rt);
}

static void test_identity_api_error_is_exit2(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    identity_fail = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_AWS, "identity API error is exit 2");
    CHECK(!run_called, "no RunInstances when identity cannot be verified");
    free_runtime(&rt);
}

static void test_cert_bucket_exported(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    cert_bucket_enabled = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "launch with cert bucket output exits 0");
    CHECK(any_ssh_contains("STACKCTL_BUCKET_CERT='demo-cert-bucket'"),
          "setup env exports STACKCTL_BUCKET_CERT when the output is present");
    free_runtime(&rt);
}

static void test_cert_bucket_absent_when_disabled(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "launch without cert bucket output exits 0");
    CHECK(!any_ssh_contains("STACKCTL_BUCKET_CERT"),
          "setup env omits STACKCTL_BUCKET_CERT when the output is absent");
    free_runtime(&rt);
}

static void test_ddns_onbox_delivers_password(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    rt.cfg.ddns_onbox = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "DDNS_ONBOX launch exits 0");
    CHECK(last_scp_argc > 0 && strcmp(last_scp_argv[0], "scp") == 0,
          "DDNS password delivery uses scp");
    CHECK(last_scp_argc >= 2 &&
              strstr(last_scp_argv[last_scp_argc - 1], ":") != NULL &&
              strstr(last_scp_argv[last_scp_argc - 1],
                     "/tmp/.stackctl-ddns-") != NULL,
          "scp destination targets the remote staging path");
    CHECK(strcmp(scp_local_content, "ddns-secret") == 0,
          "scp source carries the SSM DDNS password");
    CHECK((scp_local_mode & 0777) == 0600,
          "local password temp file is mode 0600");
    CHECK(access(scp_local_path, F_OK) != 0,
          "local password temp file is removed after delivery");
    CHECK(ssh_install_seen,
          "remote install moves the password to the on-box 0600 path");
    CHECK(any_ssh_contains("/etc/demo-ddns/password"),
          "install targets STACKCTL_DDNS_PASSWORD_FILE");
    CHECK(any_ssh_contains("STACKCTL_DDNS_HOST='box'"),
          "setup env exports STACKCTL_DDNS_HOST when DDNS_ONBOX is enabled");
    CHECK(any_ssh_contains("STACKCTL_DDNS_DOMAIN='example.com'"),
          "setup env exports STACKCTL_DDNS_DOMAIN when DDNS_ONBOX is enabled");
    free_runtime(&rt);
}

static void test_ddns_onbox_delivery_failure_is_exit7(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    rt.cfg.ddns_onbox = 1;
    scp_fail = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_SSH, "scp transport failure is exit 7");
    CHECK(terminated("i-new"), "delivery failure terminates the instance");
    CHECK(stream_contains(rt.err, "OPERATOR_CIDR"),
          "delivery exit-7 diagnostic carries the hint");
    free_runtime(&rt);
}

static void test_no_ddns_delivery_when_off(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "default (DDNS_ONBOX=false) launch exits 0");
    CHECK(last_scp_argc == 0, "no scp when DDNS_ONBOX is disabled");
    CHECK(!any_ssh_contains("STACKCTL_DDNS_HOST"),
          "setup env omits STACKCTL_DDNS_HOST when DDNS_ONBOX is "
          "disabled");
    CHECK(!any_ssh_contains("STACKCTL_DDNS_DOMAIN"),
          "setup env omits STACKCTL_DDNS_DOMAIN when DDNS_ONBOX is "
          "disabled");
    CHECK(!any_ssh_contains("STACKCTL_DDNS_PASSWORD_FILE"),
          "setup env omits STACKCTL_DDNS_PASSWORD_FILE when DDNS_ONBOX is "
          "disabled");
    free_runtime(&rt);
}

static void test_replacement_termination_failure_names_leftovers(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    add_instance("i-old-a", "running", "198.51.100.7", "old-nonce");
    add_instance("i-old-b", "running", "198.51.100.8", "old-nonce");
    snprintf(record_ip, sizeof record_ip, "%s", "198.51.100.7");
    terminate_timeout = 1;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_CLEANUP, "unconfirmed replacement is exit 5");
    CHECK(stream_contains(rt.err, "i-old-a") &&
              stream_contains(rt.err, "i-old-b"),
          "replacement failure names every leftover instance id");
    CHECK(stream_contains(rt.err, "terminate --instance-id"),
          "replacement failure names the exact terminate command");
    free_runtime(&rt);
}

static void test_ami_preflight_checks_every_declared_arch(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(rt.cfg.arch, sizeof rt.cfg.arch, "%s", "both");
    opts.arch = "amd64";
    stack_has_ami = 1;
    stack_has_arm_ami = 0;
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE,
          "a declared arch with no AMI parameter is exit 1");
    CHECK(stream_contains(rt.err, "arm64"),
          "the failing arch is named in the diagnostic");
    CHECK(!run_called, "no spend when a declared arch has no AMI");
    free_runtime(&rt);
}

static void test_ami_preflight_names_arch_missing_from_region(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(rt.cfg.arch, sizeof rt.cfg.arch, "%s", "both");
    opts.arch = "amd64";
    stack_has_ami = 1;
    stack_has_arm_ami = 1;
    snprintf(missing_ami, sizeof missing_ami, "%s", "ami-arm");
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE,
          "a declared arch whose AMI is absent from the region is exit 1");
    CHECK(stream_contains(rt.err, "arm64"),
          "the region preflight names the failing arch");
    CHECK(!run_called, "no spend when a declared arch AMI is absent");
    free_runtime(&rt);
}

static void test_reconnect_reader_removes_staging_after_rc(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    const char *read;
    const char *remove;
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    read = strstr(captured_reconnect_cmd, "cat \"$d/rc\"");
    remove = strstr(captured_reconnect_cmd, "rm -rf \"$d\"");
    CHECK(rc == CLI_EXIT_OK, "happy path exits 0");
    CHECK(read != NULL, "reconnect reader reads $d/rc");
    CHECK(remove != NULL, "reconnect reader removes the staging dir");
    CHECK(read != NULL && remove != NULL && read < remove,
          "staging removal happens only after the rc read");
    CHECK(strstr(captured_reconnect_cmd, "|| true") != NULL,
          "cleanup is best-effort so it cannot change the reported rc");
    free_runtime(&rt);
}

static void test_launch_phase_announcements(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    state_store *store;
    char root[256];
    long pin;
    long binding;
    long build;
    int rc;

    reset_all();
    store = open_temp_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }
    make_runtime(&rt, &svc);
    rt.state = store;
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "success path with state exits 0");
    CHECK(stream_contains(rt.err, "host key pinned for i-new"),
          "a successful host-key pin is announced");
    CHECK(stream_contains(rt.err, "fingerprint SHA256:"),
          "the pin announcement includes the fingerprint");
    CHECK(stream_contains(rt.err,
                          "recorded known-hosts binding i-new -> "
                          "box.example.com (198.51.100.50)"),
          "a successful known-hosts binding write is announced");
    CHECK(stream_contains(rt.err,
                          "building the setup command (entrypoint deploy.sh, "
                          "staging /run/stackctl-setup."),
          "setup command assembly is announced before it runs");
    pin = stream_position(rt.err, "host key pinned for i-new");
    binding = stream_position(rt.err, "recorded known-hosts binding i-new");
    build = stream_position(rt.err, "building the setup command");
    CHECK(pin >= 0 && binding > pin && build > binding,
          "phase announcements appear in pin, binding, setup-build order");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_launch_progress_lines(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "progress run exits 0");
    CHECK(stream_contains(rt.err, "verifying project identity"),
          "identity guard is announced");
    CHECK(stream_contains(rt.err, "requesting a"),
          "RunInstances request is announced");
    CHECK(stream_contains(rt.err, "requested instance i-new"),
          "the new instance id is announced");
    CHECK(stream_contains(rt.err, "to be running"),
          "the running waiter is announced");
    CHECK(stream_contains(rt.err, "pinning the host key"),
          "the host-key pin is announced");
    CHECK(stream_contains(rt.err, "running setup entrypoint over SSH"),
          "the setup entrypoint start is announced with expectations");
    CHECK(stream_contains(rt.err, "10-30 minutes"),
          "the setup announcement warns it can take many minutes");
    CHECK(stream_contains(rt.err, "writing the launch record") ||
              stream_contains(rt.err, "finalising the launch record"),
          "the launch-record write is announced");
    free_runtime(&rt);
}

static void test_running_waiter_reports_elapsed_progress(void) {
    instance_runtime rt;
    instance_services svc;
    launch_options opts = default_options();
    int rc;

    reset_all();
    make_runtime(&rt, &svc);
    snprintf(record_ip, sizeof record_ip, "%s", "0.0.0.0");
    rt.wait_attempts = 4;
    wait_busy_polls = 2;

    rc = launch_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_OK, "a waiter that becomes ready exits 0");
    CHECK(stream_contains(rt.err, "waiting for instance running"),
          "elapsed-time progress is emitted while the instance boots");
    free_runtime(&rt);
}

int main(void) {
    test_missing_stack_is_exit1();
    test_empty_operator_cidr_is_exit1();
    test_missing_keyscan_is_exit1_before_spend();
    test_missing_ddns_record_is_exit1();
    test_missing_ssm_param_is_exit1();
    test_both_arch_requires_flag();
    test_type_not_allowlisted_is_exit1();
    test_happy_path_orchestration();
    test_no_spot_override();
    test_keep_old_skips_replacement();
    test_run_instances_error_is_exit2();
    test_ssh_transport_failure_is_exit7_and_terminates();
    test_ssh_error_is_exit7_with_hint();
    test_setup_failure_is_exit4();
    test_entrypoint_output_is_surfaced();
    test_setup_script_extracts_and_reinjects_env();
    test_setup_script_failure_classes_are_exit3();
    test_interrupt_exits_4_and_consumes_signal();
    test_setup_timeout_is_exit4();
    test_keep_on_failure_keeps_instance();
    test_hostkey_mismatch_is_exit3();
    test_pin_failure_is_exit3();
    test_binding_write_failure_announced();
    test_manifest_selection_honors_variant();
    test_manifest_ambiguity_is_exit1();
    test_manifest_missing_member_is_exit3();
    test_manifest_sha_mismatch_is_exit3();
    test_console_polling_retries();
    test_keyscan_retry_within_timeout();
    test_keyscan_timeout_is_exit7();
    test_rc_path_and_reconnect_contract();
    test_pinned_ami_has_no_config_fallback();
    test_replaced_ids_recorded();
    test_state_append_failure_is_cleanup();
    test_identity_mismatch_is_exit3();
    test_identity_api_error_is_exit2();
    test_cert_bucket_exported();
    test_cert_bucket_absent_when_disabled();
    test_ddns_onbox_delivers_password();
    test_ddns_onbox_delivery_failure_is_exit7();
    test_no_ddns_delivery_when_off();
    test_replacement_termination_failure_names_leftovers();
    test_ami_preflight_checks_every_declared_arch();
    test_ami_preflight_names_arch_missing_from_region();
    test_reconnect_reader_removes_staging_after_rc();
    test_launch_phase_announcements();
    test_launch_progress_lines();
    test_running_waiter_reports_elapsed_progress();

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all launch tests passed\n");
    return 0;
}
