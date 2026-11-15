/*
 * status_test.c — read-only `stackctl status` orchestration tests with an
 * injected services vtable. Covers the JSON contract, exit codes, warnings,
 * orphan detection, DDNS reporting and AWS error mapping.
 */

#include "status_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "yyjson.h"

static int failures;

#define TEST_MANIFEST                                                          \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  "     \
    "app-deployment-go-amd64.tar\n"                                            \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  "     \
    "app-deployment-go-arm64.tar\n"

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* --- fake services ------------------------------------------------------- */

static int stack_present;
static int stack_status_aws_error;
static ec2_instance fixtures[8];
static size_t fixture_count;
static int describe_fail;
static char dns_ip[64];
static int dns_missing;
static int ssm_missing;
static int manifest_missing;
static char member_missing[64];
static int list_garbage;
static char extra_release[64];
static char identity_arn[256];
static char output_buffer[16384];

static int fake_describe_stacks(cfn_client *client, const char *region,
                                const char *name, cfn_stack_list *out) {
    (void)client;
    (void)region;
    (void)name;
    if (stack_status_aws_error) {
        return EIO;
    }
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
    out->items[0].parameters = calloc(4, sizeof(cfn_parameter));
    out->items[0].outputs = calloc(1, sizeof(cfn_output));
    if (out->items[0].tags == NULL || out->items[0].parameters == NULL ||
        out->items[0].outputs == NULL) {
        return ENOMEM;
    }
    out->items[0].tag_count = 2;
    snprintf(out->items[0].tags[0].key, sizeof out->items[0].tags[0].key, "%s",
             "stackctl:release-tag");
    snprintf(out->items[0].tags[0].value,
             sizeof out->items[0].tags[0].value, "%s", "v1.2.3");
    snprintf(out->items[0].tags[1].key, sizeof out->items[0].tags[1].key, "%s",
             "stackctl:release-sha");
    snprintf(out->items[0].tags[1].value,
             sizeof out->items[0].tags[1].value, "%s",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    out->items[0].parameter_count = 4;
    snprintf(out->items[0].parameters[0].key,
             sizeof out->items[0].parameters[0].key, "%s", "ReleaseTag");
    snprintf(out->items[0].parameters[0].value,
             sizeof out->items[0].parameters[0].value, "%s", "v1.2.3");
    snprintf(out->items[0].parameters[1].key,
             sizeof out->items[0].parameters[1].key, "%s",
             "ReleaseManifestSha256");
    snprintf(out->items[0].parameters[1].value,
             sizeof out->items[0].parameters[1].value, "%s",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(out->items[0].parameters[2].key,
             sizeof out->items[0].parameters[2].key, "%s", "AmiIdAmd64");
    snprintf(out->items[0].parameters[2].value,
             sizeof out->items[0].parameters[2].value, "%s", "ami-stack");
    snprintf(out->items[0].parameters[3].key,
             sizeof out->items[0].parameters[3].key, "%s", "AmiIdArm64");
    snprintf(out->items[0].parameters[3].value,
             sizeof out->items[0].parameters[3].value, "%s",
             "ami-stack-arm");
    out->items[0].output_count = 1;
    snprintf(out->items[0].outputs[0].key,
             sizeof out->items[0].outputs[0].key, "%s", "ArtifactBucketName");
    snprintf(out->items[0].outputs[0].value,
             sizeof out->items[0].outputs[0].value, "%s",
             "demo-artifacts-123-us-east-1");
    return 0;
}

static int fake_describe_instances(ec2_client *client, const ec2_filter *filters,
                                   size_t filter_count, ec2_instance_list *out) {
    (void)client;
    (void)filters;
    (void)filter_count;
    if (describe_fail) {
        return EC2_ERR_AWS_API;
    }
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
    out->items = calloc(1, sizeof(ec2_image));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    snprintf(out->items[0].image_id, sizeof out->items[0].image_id, "%s",
             count > 0 ? ids[0] : "");
    return 0;
}

static int fake_ssm(ssm_client *client, const char *name, int decrypt,
                    ssm_parameter *out) {
    (void)client;
    (void)decrypt;
    if (ssm_missing) {
        return ENOENT;
    }
    memset(out, 0, sizeof *out);
    out->name = strdup(name);
    if (strstr(name, "ami") != NULL) {
        out->value = strdup("ami-ssm");
    } else {
        out->value = strdup("ddns-secret");
    }
    return out->name != NULL && out->value != NULL ? 0 : ENOMEM;
}

static int fake_dns(const char *domain, const char *host, char *ip,
                    bool *parked) {
    (void)domain;
    (void)host;
    if (dns_missing) {
        return ENOENT;
    }
    snprintf(ip, 64, "%s", dns_ip);
    if (parked != NULL) {
        *parked = strcmp(dns_ip, "0.0.0.0") == 0 ||
                  strcmp(dns_ip, "127.0.0.1") == 0;
    }
    return 0;
}

static int fake_dns_exists(const char *domain, const char *host, bool *exists) {
    (void)domain;
    (void)host;
    *exists = !dns_missing && dns_ip[0] != '\0';
    return 0;
}

static int fake_ip_echo(const char *url, char *ip) {
    (void)url;
    snprintf(ip, 64, "%s", "203.0.113.5");
    return 0;
}

static int fake_s3_head(s3_client *client, const char *bucket, const char *key,
                        unsigned long long *size, char *etag) {
    (void)client;
    (void)bucket;
    (void)etag;
    if (manifest_missing) {
        return ENOENT;
    }
    if (member_missing[0] != '\0' && strstr(key, member_missing) != NULL) {
        return ENOENT;
    }
    *size = 42;
    return 0;
}

static int fake_s3_get(s3_client *client, const char *bucket, const char *key,
                       char **data_out, size_t *len_out) {
    (void)client;
    (void)bucket;
    (void)key;
    if (manifest_missing) {
        return ENOENT;
    }
    *data_out = strdup(TEST_MANIFEST);
    if (*data_out == NULL) {
        return ENOMEM;
    }
    *len_out = strlen(TEST_MANIFEST);
    return 0;
}

static int fake_s3_list(s3_client *client, const char *bucket, const char *prefix,
                        s3_object_list *out) {
    (void)client;
    (void)bucket;
    (void)prefix;
    memset(out, 0, sizeof *out);
    if (extra_release[0] != '\0') {
        char key[256];

        out->items = calloc(1, sizeof(s3_object_info));
        if (out->items == NULL) {
            return ENOMEM;
        }
        out->count = 1;
        snprintf(key, sizeof key, "releases/%s/release-manifest.txt",
                 extra_release);
        out->items[0].key = strdup(key);
        return out->items[0].key != NULL ? 0 : ENOMEM;
    }
    if (!list_garbage) {
        return 0;
    }
    out->items = calloc(2, sizeof(s3_object_info));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 2;
    out->items[0].key = strdup("releases/v0.9.0/partial.tar");
    out->items[1].key = strdup("releases/v0.9.0/partial.tar.sha256");
    return 0;
}

static int fake_identity(aws_ctx *ctx, char **account, char **arn,
                         char **user_id) {
    (void)ctx;
    (void)account;
    (void)user_id;
    *arn = strdup(identity_arn[0] != '\0'
                      ? identity_arn
                      : "arn:aws:iam::123456789012:user/demo");
    return *arn != NULL ? 0 : ENOMEM;
}

/* --- harness ------------------------------------------------------------- */

static char path_dir[256];
static char identity_path[256];
static ec2_instance *fixture_at(size_t i) { return &fixtures[i]; }

static void add_instance(const char *id, const char *state, const char *ip,
                         const char *ami, const char *nonce) {
    ec2_instance *item = fixture_at(fixture_count++);

    memset(item, 0, sizeof *item);
    snprintf(item->instance_id, sizeof item->instance_id, "%s", id);
    snprintf(item->state, sizeof item->state, "%s", state);
    snprintf(item->public_ip, sizeof item->public_ip, "%s", ip);
    snprintf(item->image_id, sizeof item->image_id, "%s", ami);
    snprintf(item->tags[0].key, sizeof item->tags[0].key, "%s", "Project");
    snprintf(item->tags[0].value, sizeof item->tags[0].value, "%s", "demo");
    if (nonce != NULL) {
        snprintf(item->tags[1].key, sizeof item->tags[1].key, "%s",
                 "stackctl:launch-nonce");
        snprintf(item->tags[1].value, sizeof item->tags[1].value, "%s", nonce);
        item->tag_count = 2;
    } else {
        item->tag_count = 1;
    }
}

static void setup_fake_path(void) {
    const char *tools[] = {"ssh", "scp", "ssh-keyscan", "bazel"};
    size_t tool_count = sizeof tools / sizeof tools[0];

    snprintf(path_dir, sizeof path_dir, "/tmp/stackctl-status-path-XXXXXX");
    if (mkdtemp(path_dir) == NULL) {
        snprintf(path_dir, sizeof path_dir, "%s", "/tmp");
        return;
    }
    for (size_t i = 0; i < tool_count; i++) {
        char file[300];

        snprintf(file, sizeof file, "%s/%s", path_dir, tools[i]);
        FILE *f = fopen(file, "w");
        if (f != NULL) {
            fputs("#!/bin/sh\n", f);
            fclose(f);
            chmod(file, 0700);
        }
    }
    setenv("PATH", path_dir, 1);

    snprintf(identity_path, sizeof identity_path, "/tmp/stackctl-id-XXXXXX");
    int fd = mkstemp(identity_path);
    if (fd >= 0) {
        close(fd);
    }
}

static void cleanup_fake_path(void) {
    if (identity_path[0] != '\0') {
        unlink(identity_path);
    }
    if (path_dir[0] != '\0' && strstr(path_dir, "XXXXXX") == NULL) {
        const char *tools[] = {"ssh", "scp", "ssh-keyscan", "bazel"};
        size_t tool_count = sizeof tools / sizeof tools[0];
        for (size_t i = 0; i < tool_count; i++) {
            char file[300];
            snprintf(file, sizeof file, "%s/%s", path_dir, tools[i]);
            unlink(file);
        }
        rmdir(path_dir);
    }
}

static state_store *open_temp_state(char *root, size_t cap) {
    state_store *store = NULL;

    snprintf(root, cap, "/tmp/stackctl-status-state-XXXXXX");
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
    chmod(dir, 0700);
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

static void reset_all(void) {
    stack_present = 0;
    stack_status_aws_error = 0;
    memset(fixtures, 0, sizeof fixtures);
    fixture_count = 0;
    describe_fail = 0;
    memset(dns_ip, 0, sizeof dns_ip);
    dns_missing = 0;
    ssm_missing = 0;
    manifest_missing = 0;
    memset(member_missing, 0, sizeof member_missing);
    list_garbage = 0;
    memset(extra_release, 0, sizeof extra_release);
    memset(identity_arn, 0, sizeof identity_arn);
    unsetenv("STACKCTL_VERSION_FILE");
    unsetenv("RUNFILES_DIR");
    memset(output_buffer, 0, sizeof output_buffer);
}

static void make_runtime(instance_runtime *rt, instance_services *svc,
                         int json) {
    instance_config cfg;

    memset(&cfg, 0, sizeof cfg);
    snprintf(cfg.project, sizeof cfg.project, "%s", "demo");
    snprintf(cfg.region, sizeof cfg.region, "%s", "us-east-1");
    snprintf(cfg.arch, sizeof cfg.arch, "%s", "amd64");
    snprintf(cfg.ami_policy, sizeof cfg.ami_policy, "%s", "ssm");
    snprintf(cfg.ami_ssm_amd64, sizeof cfg.ami_ssm_amd64, "%s", "/ami/float");
    snprintf(cfg.key_name, sizeof cfg.key_name, "%s", "demo-key");
    snprintf(cfg.ssh_identity, sizeof cfg.ssh_identity, "%s", identity_path);
    snprintf(cfg.operator_cidr, sizeof cfg.operator_cidr, "%s", "203.0.113.0/24");
    snprintf(cfg.ddns_host, sizeof cfg.ddns_host, "%s", "box");
    snprintf(cfg.ddns_domain, sizeof cfg.ddns_domain, "%s", "example.com");
    snprintf(cfg.ip_echo_url, sizeof cfg.ip_echo_url, "%s", "https://echo");

    memset(svc, 0, sizeof *svc);
    svc->cfn_describe_stacks = fake_describe_stacks;
    svc->ec2_describe_instances = fake_describe_instances;
    svc->ec2_describe_images = fake_describe_images;
    svc->ssm_get_parameter = fake_ssm;
    svc->dns_a_record = fake_dns;
    svc->dns_record_exists = fake_dns_exists;
    svc->ddns_ip_echo = fake_ip_echo;
    svc->s3_head_object = fake_s3_head;
    svc->s3_get_object = fake_s3_get;
    svc->s3_list_objects = fake_s3_list;
    svc->iam_get_caller_identity = fake_identity;

    instance_runtime_init(rt, &cfg, NULL, svc, json, 0, 0);
    rt->out = tmpfile();
    rt->err = tmpfile();
}

static void slurp(instance_runtime *rt) {
    long size;

    if (rt->out == NULL) {
        return;
    }
    fflush(rt->out);
    rewind(rt->out);
    size = fread(output_buffer, 1, sizeof output_buffer - 1, rt->out);
    output_buffer[size > 0 ? size : 0] = '\0';
}

static void free_runtime(instance_runtime *rt) {
    if (rt->out != NULL) {
        fclose(rt->out);
    }
    if (rt->err != NULL) {
        fclose(rt->err);
    }
}

static int has(const char *needle) { return strstr(output_buffer, needle) != NULL; }

/* --- tests --------------------------------------------------------------- */

static void test_never_deployed_json(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "never-deployed status exits 0");
    CHECK(has("\"schema_version\""), "JSON has schema_version");
    CHECK(has("\"stack\": null"), "absent stack is null");
    free_runtime(&rt);
}

static void test_instance_and_ami_reported(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    add_instance("i-1", "running", "198.51.100.7", "ami-live", NULL);
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.7");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "deployed status exits 0");
    CHECK(has("\"id\": \"i-1\""), "instance id reported");
    CHECK(has("\"ami\": \"ami-live\""), "instance AMI reported");
    CHECK(has("\"release\"") && has("v1.2.3"), "release tag reported");
    CHECK(has("\"warnings\": []"), "no warnings for a healthy project");
    free_runtime(&rt);
}

static void test_ddns_mismatch_is_warning(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    add_instance("i-1", "running", "198.51.100.7", "ami-live", "nonce-1");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.99");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "DDNS mismatch is a warning, not an error");
    CHECK(has("DDNS"), "warning mentions DDNS");
    free_runtime(&rt);
}

static void test_missing_record_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    dns_missing = 1;

    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing DDNS record is exit 1");
    free_runtime(&rt);
}

static void test_missing_ssm_param_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    ssm_missing = 1;

    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing SSM parameter is exit 1");
    free_runtime(&rt);
}

static void test_aws_error_is_exit2(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    describe_fail = 1;

    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_AWS, "AWS describe failure is exit 2");
    free_runtime(&rt);
}

static void test_empty_operator_cidr_warns(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    snprintf(rt.cfg.operator_cidr, sizeof rt.cfg.operator_cidr, "%s", "");
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "empty OPERATOR_CIDR is a warning");
    CHECK(has("OPERATOR_CIDR"), "warning mentions OPERATOR_CIDR");
    free_runtime(&rt);
}

static void test_orphan_detected(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    add_instance("i-1", "running", "198.51.100.7", "ami-live", "orphan-nonce");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.7");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "orphan detection is a warning");
    CHECK(has("orphan"), "warning mentions orphan");
    free_runtime(&rt);
}

static void test_missing_manifest_warns(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    add_instance("i-1", "running", "198.51.100.7", "ami-live", "nonce-1");
    snprintf(dns_ip, sizeof dns_ip, "%s", "198.51.100.7");
    manifest_missing = 1;

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "missing release manifest is a warning");
    CHECK(has("manifest") || has("release"), "warning mentions release health");
    free_runtime(&rt);
}

static void test_identity_guard_mismatch_is_exit3(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    snprintf(identity_arn, sizeof identity_arn, "%s",
             "arn:aws:iam::123456789012:user/other");

    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_VERIFY, "identity guard mismatch is exit 3");
    free_runtime(&rt);
}

static state_store *seed_binding_state(char *root, size_t cap) {
    state_store *store = open_temp_state(root, cap);
    kh_binding binding;

    if (store == NULL) {
        return NULL;
    }
    memset(&binding, 0, sizeof binding);
    snprintf(binding.instance_id, sizeof binding.instance_id, "%s", "i-bind");
    snprintf(binding.host_key, sizeof binding.host_key, "%s", "SHA256:abc");
    snprintf(binding.fqdn, sizeof binding.fqdn, "%s", "box.example.com");
    snprintf(binding.ip, sizeof binding.ip, "%s", "198.51.100.9");
    (void)state_binding_put(store, &binding);
    return store;
}

static void test_bindings_json_parses(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    state_store *store;
    char root[256];
    yyjson_doc *doc;
    yyjson_val *root_val;
    yyjson_val *bindings;
    yyjson_val *first;
    int rc;

    reset_all();
    store = seed_binding_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }

    make_runtime(&rt, &svc, 1);
    rt.state = store;
    stack_present = 1;
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");
    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "status with bindings exits 0");
    CHECK(strstr(output_buffer, "binding: ") == NULL,
          "JSON mode never writes raw binding text to stdout");

    doc = yyjson_read(output_buffer, strlen(output_buffer), 0);
    CHECK(doc != NULL, "status --json output parses as JSON");
    if (doc != NULL) {
        root_val = yyjson_doc_get_root(doc);
        bindings = yyjson_obj_get(root_val, "bindings");
        CHECK(bindings != NULL && yyjson_is_arr(bindings),
              "bindings is a JSON array");
        if (bindings != NULL && yyjson_is_arr(bindings)) {
            CHECK(yyjson_arr_size(bindings) == 1, "one binding reported");
            first = yyjson_arr_get_first(bindings);
            CHECK(first != NULL && yyjson_is_obj(first),
                  "binding entry is an object");
            if (first != NULL && yyjson_is_obj(first)) {
                CHECK(strcmp(yyjson_get_str(
                                 yyjson_obj_get(first, "instance_id")),
                             "i-bind") == 0,
                      "binding instance id reported");
                CHECK(strcmp(yyjson_get_str(yyjson_obj_get(first, "fqdn")),
                             "box.example.com") == 0,
                      "binding fqdn reported");
            }
        }
        yyjson_doc_free(doc);
    }
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_bindings_text_reported(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    state_store *store;
    char root[256];
    int rc;

    reset_all();
    store = seed_binding_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }

    make_runtime(&rt, &svc, 0);
    rt.state = store;
    stack_present = 1;
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");
    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "text status with bindings exits 0");
    CHECK(has("binding: i-bind box.example.com -> 198.51.100.9"),
          "text mode prints the bindings line");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_release_member_missing_warns(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");
    snprintf(member_missing, sizeof member_missing, "%s",
             "app-deployment-go-arm64.tar");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "missing release member is a warning");
    CHECK(has("release member") && has("go-arm64"),
          "warning names the missing release member");
    free_runtime(&rt);
}

static void test_garbage_prefix_listed(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");
    list_garbage = 1;

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "garbage prefixes are a warning");
    CHECK(has("garbage prefix") && has("releases/v0.9.0/"),
          "manifest-less prefix is listed");
    CHECK(has("garbage_prefixes"), "JSON lists garbage prefixes");
    free_runtime(&rt);
}

static void test_state_dir_unwritable_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    state_store *store;
    char root[256];
    int rc;

    if (geteuid() == 0) {
        return; /* root bypasses directory permission bits */
    }
    reset_all();
    store = open_temp_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }
    CHECK(chmod(state_dir(store), 0500) == 0, "state dir made read-only");

    make_runtime(&rt, &svc, 1);
    rt.state = store;
    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "unwritable state dir is exit 1");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void seed_launch_record(state_store *store, const char *instance_id,
                               const char *nonce) {
    state_launch_record record;

    memset(&record, 0, sizeof record);
    snprintf(record.instance_id, sizeof record.instance_id, "%s", instance_id);
    snprintf(record.nonce, sizeof record.nonce, "%s", nonce);
    snprintf(record.fqdn, sizeof record.fqdn, "%s", "box.example.com");
    snprintf(record.ip, sizeof record.ip, "%s", "198.51.100.7");
    CHECK(state_launch_record_append(store, &record) == 0,
          "seed launch record");
}

static void seed_old_launch_record(state_store *store, const char *instance_id,
                                   const char *nonce) {
    FILE *file = fopen(state_launch_records_path(store), "a");

    CHECK(file != NULL, "open launch records for old seed");
    if (file == NULL) {
        return;
    }
    fprintf(file, "2000-01-01T00:00:00Z\t%s\t%s\tbox.example.com\t198.51.100.7\t\n",
            instance_id, nonce);
    fclose(file);
}

static void test_version_reported(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    char path[] = "/tmp/stackctl-version-XXXXXX";
    int fd;
    int rc;

    reset_all();
    fd = mkstemp(path);
    CHECK(fd >= 0, "temp VERSION file");
    if (fd >= 0) {
        FILE *file = fdopen(fd, "w");

        if (file != NULL) {
            fputs("v9.9.9\n", file);
            fclose(file);
        }
        CHECK(setenv("STACKCTL_VERSION_FILE", path, 1) == 0,
              "set VERSION override");
    }
    make_runtime(&rt, &svc, 1);
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "status with VERSION override exits 0");
    CHECK(has("\"version\": \"v9.9.9\""), "JSON reports the resolved version");
    free_runtime(&rt);
    unlink(path);
}

static void test_stack_parameters_and_tags_json(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "status with stack parameters exits 0");
    CHECK(has("\"parameters\""), "stack parameters reported");
    CHECK(has("\"ReleaseTag\"") && has("\"AmiIdArm64\""),
          "key stack parameters reported");
    CHECK(has("\"tags\""), "stack tags reported alongside parameters");
    free_runtime(&rt);
}

static void test_pinned_release_not_latest_warns(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");
    snprintf(extra_release, sizeof extra_release, "%s", "v2.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "pinned release behind latest is a warning");
    CHECK(has("\"latest\": \"v2.0.0\""), "latest release prefix reported");
    CHECK(has("not the latest"), "warning names the newer release");
    free_runtime(&rt);
}

static void test_ami_drift_warns(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    make_runtime(&rt, &svc, 1);
    stack_present = 1;
    snprintf(rt.cfg.ami_policy, sizeof rt.cfg.ami_policy, "%s", "pinned");
    snprintf(rt.cfg.ami_id_amd64, sizeof rt.cfg.ami_id_amd64, "%s",
             "ami-config");
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "AMI drift is a warning");
    CHECK(has("AMI drift") && has("run deploy to apply"),
          "warning explains how to apply the pin");
    free_runtime(&rt);
}

static void test_multi_writer_warns_unconditionally(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    state_store *store;
    char root[256];
    int rc;

    reset_all();
    store = open_temp_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }
    seed_launch_record(store, "i-1", "nonce-1");
    seed_launch_record(store, "i-2", "nonce-2");

    make_runtime(&rt, &svc, 1);
    rt.state = store;
    snprintf(rt.cfg.ddns_host, sizeof rt.cfg.ddns_host, "%s", "");
    snprintf(rt.cfg.ddns_domain, sizeof rt.cfg.ddns_domain, "%s", "");
    stack_present = 1;
    add_instance("i-1", "running", "198.51.100.7", "ami-live", "nonce-1");
    add_instance("i-2", "running", "198.51.100.8", "ami-live", "nonce-2");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "multi-writer is a warning");
    CHECK(has("multi-writer"),
          "multi-writer warns without DDNS configured");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_multi_writer_old_nonces_are_quiet(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    state_store *store;
    char root[256];
    int rc;

    reset_all();
    store = open_temp_state(root, sizeof root);
    CHECK(store != NULL, "temp state store opens");
    if (store == NULL) {
        return;
    }
    seed_old_launch_record(store, "i-1", "nonce-1");
    seed_old_launch_record(store, "i-2", "nonce-2");

    make_runtime(&rt, &svc, 1);
    rt.state = store;
    snprintf(rt.cfg.ddns_host, sizeof rt.cfg.ddns_host, "%s", "");
    snprintf(rt.cfg.ddns_domain, sizeof rt.cfg.ddns_domain, "%s", "");
    stack_present = 1;
    add_instance("i-1", "running", "198.51.100.7", "ami-live", "nonce-1");
    add_instance("i-2", "running", "198.51.100.8", "ami-live", "nonce-2");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "old nonces exit 0");
    CHECK(!has("multi-writer"),
          "nonces older than 1 h do not warn");
    free_runtime(&rt);
    close_temp_state(store, root);
}

static void test_bazel_preflight_reports(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    char repo[] = "/tmp/stackctl-status-repo-XXXXXX";
    char marker[300];
    FILE *file;
    int rc;

    reset_all();
    CHECK(mkdtemp(repo) != NULL, "temp repo root");
    snprintf(marker, sizeof marker, "%s/MODULE.bazel", repo);
    file = fopen(marker, "w");
    if (file != NULL) {
        fclose(file);
    }

    opts.config_dir = repo;
    opts.bazel_command = "bazel";
    make_runtime(&rt, &svc, 1);
    snprintf(dns_ip, sizeof dns_ip, "%s", "0.0.0.0");

    rc = status_execute(&rt, &opts);
    slurp(&rt);

    CHECK(rc == CLI_EXIT_OK, "bazel preflight passes");
    CHECK(has("\"bazel\"") && has("\"command_found\": true"),
          "bazel command availability reported");
    CHECK(has("\"repo_root\"") && has(repo), "repo root reported");
    free_runtime(&rt);
    unlink(marker);
    rmdir(repo);
}

static void test_missing_bazel_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    int rc;

    reset_all();
    opts.bazel_command = "definitely-not-a-tool-xyz";
    make_runtime(&rt, &svc, 1);

    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "missing BAZEL_COMMAND is exit 1");
    free_runtime(&rt);
}

static void test_missing_repo_root_is_exit1(void) {
    instance_runtime rt;
    instance_services svc;
    status_options opts = {0};
    char dir[] = "/tmp/stackctl-status-norepo-XXXXXX";
    int rc;

    reset_all();
    CHECK(mkdtemp(dir) != NULL, "temp dir without MODULE.bazel");
    opts.config_dir = dir;
    make_runtime(&rt, &svc, 1);

    rc = status_execute(&rt, &opts);

    CHECK(rc == CLI_EXIT_USAGE, "unresolvable repo root is exit 1");
    free_runtime(&rt);
    rmdir(dir);
}

int main(void) {
    setup_fake_path();

    test_never_deployed_json();
    test_instance_and_ami_reported();
    test_ddns_mismatch_is_warning();
    test_missing_record_is_exit1();
    test_missing_ssm_param_is_exit1();
    test_aws_error_is_exit2();
    test_empty_operator_cidr_warns();
    test_orphan_detected();
    test_missing_manifest_warns();
    test_identity_guard_mismatch_is_exit3();
    test_bindings_json_parses();
    test_bindings_text_reported();
    test_release_member_missing_warns();
    test_garbage_prefix_listed();
    test_state_dir_unwritable_is_exit1();
    test_version_reported();
    test_stack_parameters_and_tags_json();
    test_pinned_release_not_latest_warns();
    test_ami_drift_warns();
    test_multi_writer_warns_unconditionally();
    test_multi_writer_old_nonces_are_quiet();
    test_bazel_preflight_reports();
    test_missing_bazel_is_exit1();
    test_missing_repo_root_is_exit1();

    cleanup_fake_path();
    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all status tests passed\n");
    return 0;
}
