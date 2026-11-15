/*
 * lifecycle_test.c — end-to-end instance lifecycle over one fake world.
 *
 * Drives launch -> status -> start/stop -> terminate through the verbs'
 * documented orchestration seams while sharing a single in-memory AWS world and
 * a real on-disk state + known-hosts store under $XDG_STATE_HOME. Everything
 * external is a fake: no network, no EC2/S3/SSM, no DNS, no ssh.
 *
 * Covers the spec §4 acceptance flows: launch manifest member selection,
 * DDNS snapshot/update/verify, console+ssh-keyscan host-key pinning and the
 * known-hosts binding, launch-replace semantics, launch idempotency nonce,
 * the setup env contract, status JSON validity and secret redaction,
 * start/stop target selection and re-verification, terminate safety and
 * park semantics, cleanup exit codes, and failure paths.
 */

#include "core/cli/launch/common/instance.h"
#include "core/cli/launch/launch_internal.h"
#include "core/cli/startstop/startstop_internal.h"
#include "core/cli/status/status_internal.h"
#include "core/cli/terminate/terminate_internal.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/crypto/crypto.h"
#include "core/knownhosts/knownhosts.h"
#include "core/state/state.h"
#include "yyjson.h"

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define SHA_A                                                                  \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SHA_B                                                                  \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define SHA_C                                                                  \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

#define AMBIGUOUS_MANIFEST                                                     \
    SHA_A "  app-deployment-go-amd64.tar\n"                                    \
          SHA_C "  app-deployment-c-amd64.tar\n"

#define KEY_ONE                                                                \
    "203.0.113.20 ssh-ed25519 "                                                \
    "AAAAC3NzaC1lZDI1NTE5AAAAIJ8Lk7v5H0m0b2w7p8eQ0f3o5w5m6v8j3h9r2s1t4u6v"

/* ------------------------------------------------------------------------- */
/* Fake world                                                                */
/* ------------------------------------------------------------------------- */

typedef struct world {
    ec2_instance instances[8];
    size_t instance_count;
    char dns_ip[64];
    char operator_ip[64];
    int ddns_calls;
    int dns_record_exists;
    int console_has_fingerprints;
    int describe_fail;
    int run_fail;
    int wait_timed_out;
    int terminate_wait_timed_out;
    int terminate_fail;
    int ddns_fail;
    int identity_ok;
    int s3_missing;
    char manifest[1024];
    char manifest_sha[65];
    char last_terminated[8][24];
    size_t last_terminated_count;
    char last_run_nonce[64];
    char last_run_client_token[65];
    char last_run_name[128];
    char last_ssh_command[8192];
    int ssh_calls;
    int keyscan_calls;
    int console_calls;
    int terminate_confirmed;
} world;

static world W;

static void world_reset(void) {
    memset(&W, 0, sizeof W);
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "198.51.100.10");
    snprintf(W.operator_ip, sizeof W.operator_ip, "%s", "203.0.113.5");
    W.dns_record_exists = 1;
    W.console_has_fingerprints = 1;
    W.identity_ok = 1;
    snprintf(W.manifest, sizeof W.manifest, "%s", AMBIGUOUS_MANIFEST);
}

static void set_manifest(world *w, const char *text) {
    uint8_t digest[32];

    snprintf(w->manifest, sizeof w->manifest, "%s", text);
    crypto_sha256(text, strlen(text), digest);
    for (size_t i = 0; i < 32; i++) {
        snprintf(w->manifest_sha + i * 2, 3, "%02x", digest[i]);
    }
}

static ec2_instance *world_add(const char *id, const char *state,
                               const char *ip, const char *nonce) {
    ec2_instance *item = &W.instances[W.instance_count++];

    memset(item, 0, sizeof *item);
    snprintf(item->instance_id, sizeof item->instance_id, "%s", id);
    snprintf(item->state, sizeof item->state, "%s", state);
    snprintf(item->public_ip, sizeof item->public_ip, "%s", ip);
    snprintf(item->tags[0].key, sizeof item->tags[0].key, "%s", "Project");
    snprintf(item->tags[0].value, sizeof item->tags[0].value, "%s", "demo");
    snprintf(item->tags[1].key, sizeof item->tags[1].key, "%s", "Name");
    snprintf(item->tags[1].value, sizeof item->tags[1].value, "%s",
             "app.example.com");
    item->tag_count = 2;
    if (nonce != NULL) {
        snprintf(item->tags[2].key, sizeof item->tags[2].key, "%s",
                 "stackctl:launch-nonce");
        snprintf(item->tags[2].value, sizeof item->tags[2].value, "%s", nonce);
        item->tag_count = 3;
    }
    return item;
}

static ec2_instance *world_find(const char *id) {
    for (size_t i = 0; i < W.instance_count; i++) {
        if (strcmp(W.instances[i].instance_id, id) == 0) {
            return &W.instances[i];
        }
    }
    return NULL;
}

static void world_remove_terminated(void) {
    size_t out = 0;

    for (size_t i = 0; i < W.instance_count; i++) {
        if (strcmp(W.instances[i].state, "terminated") != 0) {
            if (out != i) {
                W.instances[out] = W.instances[i];
            }
            out++;
        }
    }
    W.instance_count = out;
}

/* ------------------------------------------------------------------------- */
/* Fake services                                                             */
/* ------------------------------------------------------------------------- */

static int fake_describe_stacks(cfn_client *client, const char *region,
                                const char *name, cfn_stack_list *out) {
    (void)client;
    (void)region;
    (void)name;
    memset(out, 0, sizeof *out);
    out->items = calloc(1, sizeof(cfn_stack));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = 1;
    cfn_stack *stack = &out->items[0];
    snprintf(stack->stack_name, sizeof stack->stack_name, "%s", "demo-infra");
    stack->status = CFN_STACK_STATUS_CREATE_COMPLETE;
    stack->tags = calloc(2, sizeof(cfn_tag));
    stack->parameters = calloc(1, sizeof(cfn_parameter));
    stack->outputs = calloc(4, sizeof(cfn_output));
    if (stack->tags == NULL || stack->parameters == NULL ||
        stack->outputs == NULL) {
        return ENOMEM;
    }
    stack->tag_count = 2;
    snprintf(stack->tags[0].key, sizeof stack->tags[0].key, "%s",
             "stackctl:release-tag");
    snprintf(stack->tags[0].value, sizeof stack->tags[0].value, "%s", "v1.2.3");
    snprintf(stack->tags[1].key, sizeof stack->tags[1].key, "%s",
             "stackctl:release-sha");
    snprintf(stack->tags[1].value, sizeof stack->tags[1].value, "%s",
             W.manifest_sha);
    stack->parameter_count = 1;
    snprintf(stack->parameters[0].key, sizeof stack->parameters[0].key, "%s",
             "AmiIdAmd64");
    snprintf(stack->parameters[0].value,
             sizeof stack->parameters[0].value, "%s", "ami-stack");
    stack->output_count = 4;
    static const char *const out_keys[] = {
        "ArtifactBucketName", "SubnetId", "SecurityGroupId",
        "InstanceProfileName"};
    static const char *const out_vals[] = {
        "demo-artifacts-123-us-east-1", "subnet-1", "sg-1", "demo-instance"};
    for (size_t i = 0; i < 4; i++) {
        snprintf(stack->outputs[i].key, sizeof stack->outputs[i].key, "%s",
                 out_keys[i]);
        snprintf(stack->outputs[i].value, sizeof stack->outputs[i].value, "%s",
                 out_vals[i]);
    }
    return 0;
}

static int fake_describe_instances(ec2_client *client, const ec2_filter *filters,
                                   size_t filter_count, ec2_instance_list *out) {
    (void)client;
    (void)filters;
    (void)filter_count;
    memset(out, 0, sizeof *out);
    if (W.describe_fail) {
        return EC2_ERR_AWS_API;
    }
    if (W.instance_count > 0) {
        out->items = calloc(W.instance_count, sizeof(ec2_instance));
        if (out->items == NULL) {
            return ENOMEM;
        }
        memcpy(out->items, W.instances, W.instance_count * sizeof(ec2_instance));
        out->count = W.instance_count;
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
             count > 0 ? ids[0] : "ami-stack");
    snprintf(out->items[0].root_device_name,
             sizeof out->items[0].root_device_name, "%s", "/dev/sda1");
    return 0;
}

static int fake_run_instances(ec2_client *client, const ec2_run_spec *spec,
                              ec2_run_result *out) {
    (void)client;
    if (W.run_fail) {
        return EC2_ERR_AWS_API;
    }
    snprintf(W.last_run_nonce, sizeof W.last_run_nonce, "%s",
             spec->launch_nonce);
    snprintf(W.last_run_client_token, sizeof W.last_run_client_token, "%s",
             spec->client_token);
    snprintf(W.last_run_name, sizeof W.last_run_name, "%s", spec->name);
    CHECK(spec->project != NULL && strcmp(spec->project, "demo") == 0,
          "RunInstances Project tag");
    CHECK(spec->launch_nonce != NULL, "RunInstances launch nonce");
    CHECK(spec->root_volume_size_gb > 0, "RunInstances root volume size");
    memset(out, 0, sizeof *out);
    snprintf(out->instance_id, sizeof out->instance_id, "%s", "i-new");
    snprintf(out->state, sizeof out->state, "%s", "pending");
    (void)world_add("i-new", "pending", "", spec->launch_nonce);
    return 0;
}

static int fake_wait_running(ec2_client *client, const char *instance_id,
                             int attempts, int interval, ec2_instance *out,
                             int *timed_out) {
    (void)client;
    (void)attempts;
    (void)interval;
    if (W.wait_timed_out) {
        *timed_out = 1;
        return 0;
    }
    *timed_out = 0;
    memset(out, 0, sizeof *out);
    ec2_instance *item = world_find(instance_id);
    if (item != NULL) {
        snprintf(item->state, sizeof item->state, "%s", "running");
        snprintf(item->public_ip, sizeof item->public_ip, "%s",
                 "203.0.113.20");
        *out = *item;
    } else {
        snprintf(out->instance_id, sizeof out->instance_id, "%s", instance_id);
        snprintf(out->state, sizeof out->state, "%s", "running");
        snprintf(out->public_ip, sizeof out->public_ip, "%s", "203.0.113.20");
    }
    return 0;
}

static int fake_terminate(ec2_client *client, const char *const *ids,
                          size_t id_count, ec2_terminate_result *out) {
    (void)client;
    if (W.terminate_fail) {
        return EC2_ERR_AWS_API;
    }
    W.terminate_confirmed = 1;
    memset(out, 0, sizeof *out);
    out->items = calloc(id_count, sizeof(ec2_terminate_entry));
    if (out->items == NULL) {
        return ENOMEM;
    }
    out->count = id_count;
    W.last_terminated_count = id_count;
    for (size_t i = 0; i < id_count; i++) {
        snprintf(out->items[i].instance_id, sizeof out->items[i].instance_id,
                 "%s", ids[i]);
        snprintf(W.last_terminated[i], sizeof W.last_terminated[i], "%s",
                 ids[i]);
        ec2_instance *item = world_find(ids[i]);
        if (item != NULL) {
            snprintf(item->state, sizeof item->state, "%s", "shutting-down");
        }
    }
    return 0;
}

static int fake_wait_terminated(ec2_client *client, const char *const *ids,
                                size_t id_count, int attempts, int interval,
                                int *timed_out) {
    (void)client;
    (void)ids;
    (void)attempts;
    (void)interval;
    if (W.terminate_wait_timed_out) {
        *timed_out = 1;
        return 0;
    }
    *timed_out = 0;
    for (size_t i = 0; i < id_count; i++) {
        ec2_instance *item = world_find(ids[i]);
        if (item != NULL) {
            snprintf(item->state, sizeof item->state, "%s", "terminated");
        }
    }
    world_remove_terminated();
    return 0;
}

static int fake_console(ec2_client *client, const char *instance_id,
                        char **out) {
    (void)client;
    (void)instance_id;
    W.console_calls++;
    *out = NULL;
    if (!W.console_has_fingerprints) {
        *out = strdup("no fingerprints here\n");
        return 0;
    }
    {
        char fingerprint[INST_FINGERPRINT_MAX] = {0};
        char text[512];

        if (instance_key_fingerprint(KEY_ONE, fingerprint,
                                     sizeof fingerprint) != 0) {
            return EINVAL;
        }
        snprintf(text, sizeof text,
                 "-----BEGIN SSH HOST KEY FINGERPRINTS-----\n"
                 "256 %s no comment (ED25519)\n"
                 "-----END SSH HOST KEY FINGERPRINTS-----\n",
                 fingerprint);
        *out = strdup(text);
    }
    return 0;
}

static int fake_keyscan(const char *ip, int port, char **line_out) {
    (void)ip;
    (void)port;
    W.keyscan_calls++;
    *line_out = strdup(KEY_ONE);
    return *line_out != NULL ? 0 : ENOMEM;
}

static int fake_ssh_exec(char *const argv[], int timeout,
                         const sshc_sentinel_spec *sentinel, int *remote_rc) {
    (void)timeout;
    (void)sentinel;
    W.ssh_calls++;
    if (remote_rc != NULL) {
        *remote_rc = 0;
    }
    W.last_ssh_command[0] = '\0';
    for (size_t i = 0; argv != NULL && argv[i] != NULL; i++) {
        size_t used = strlen(W.last_ssh_command);
        snprintf(W.last_ssh_command + used, sizeof W.last_ssh_command - used,
                 "%s%s", used > 0 ? " " : "", argv[i]);
    }
    return 0;
}

static int fake_dns(const char *domain, const char *host, char *ip,
                    bool *parked) {
    (void)domain;
    (void)host;
    if (W.dns_ip[0] == '\0') {
        return ENOENT;
    }
    snprintf(ip, 64, "%s", W.dns_ip);
    if (parked != NULL) {
        *parked = strcmp(W.dns_ip, "0.0.0.0") == 0 ||
                  strcmp(W.dns_ip, "127.0.0.1") == 0;
    }
    return 0;
}

static int fake_dns_exists(const char *domain, const char *host, bool *exists) {
    (void)domain;
    (void)host;
    *exists = W.dns_record_exists != 0;
    return 0;
}

static int fake_ddns(const char *host, const char *domain, const char *password,
                     const char *ip, bool *updated) {
    (void)host;
    (void)domain;
    (void)password;
    W.ddns_calls++;
    if (W.ddns_fail) {
        return EIO;
    }
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", ip);
    *updated = true;
    return 0;
}

static int fake_ip_echo(const char *url, char *ip) {
    (void)url;
    snprintf(ip, 64, "%s", W.operator_ip);
    return 0;
}

static int fake_ssm(ssm_client *client, const char *name, int decrypt,
                    ssm_parameter *out) {
    (void)client;
    (void)decrypt;
    memset(out, 0, sizeof *out);
    out->name = strdup(name);
    if (strstr(name, "ddns/password") != NULL) {
        out->value = strdup("ddns-secret");
    } else {
        out->value = strdup("ami-ssm");
    }
    return out->name != NULL && out->value != NULL ? 0 : ENOMEM;
}

static int fake_s3_head(s3_client *client, const char *bucket, const char *key,
                        unsigned long long *size, char *etag) {
    (void)client;
    (void)bucket;
    (void)key;
    if (W.s3_missing) {
        return ENOENT;
    }
    *size = 42;
    if (etag != NULL) {
        snprintf(etag, 64, "%s", "etag");
    }
    return 0;
}

static int fake_s3_get(s3_client *client, const char *bucket, const char *key,
                       char **data_out, size_t *len_out) {
    (void)client;
    (void)bucket;
    (void)key;
    if (W.s3_missing) {
        return ENOENT;
    }
    *data_out = strdup(W.manifest);
    *len_out = strlen(W.manifest);
    return *data_out != NULL ? 0 : ENOMEM;
}

static int fake_identity(aws_ctx *ctx, char **account, char **arn,
                         char **user_id) {
    (void)ctx;
    (void)account;
    (void)user_id;
    *arn = strdup(W.identity_ok ? "arn:aws:iam::123456789012:user/demo"
                                : "arn:aws:iam::123456789012:user/other");
    return *arn != NULL ? 0 : ENOMEM;
}

/* ------------------------------------------------------------------------- */
/* Runtime fixture                                                           */
/* ------------------------------------------------------------------------- */

typedef struct fixture {
    char root[PATH_MAX];
    char state_root[PATH_MAX];
    char identity[PATH_MAX];
    char path_dir[PATH_MAX];
    char old_path[PATH_MAX];
    state_store *state;
} fixture;

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
            (void)mkdir(buffer, 0700);
            *p = '/';
        }
    }
    (void)mkdir(buffer, 0700);
}

static void write_exec(const char *path) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    fputs("#!/bin/sh\nexit 0\n", file);
    fclose(file);
    if (chmod(path, 0755) != 0) {
        perror(path);
        exit(1);
    }
}

static void fixture_init(fixture *fx) {
    char template[] = "/tmp/stackctl-lifecycle-XXXXXX";
    char *root = mkdtemp(template);
    char path[PATH_MAX];

    memset(fx, 0, sizeof *fx);
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof fx->root, "%s", root);
    snprintf(fx->state_root, sizeof fx->state_root, "%s/state", fx->root);
    snprintf(fx->path_dir, sizeof fx->path_dir, "%s/bin", fx->root);
    mkdir_p(fx->state_root);
    mkdir_p(fx->path_dir);
    snprintf(path, sizeof path, "%s/ssh", fx->path_dir);
    write_exec(path);
    snprintf(path, sizeof path, "%s/scp", fx->path_dir);
    write_exec(path);
    snprintf(path, sizeof path, "%s/ssh-keyscan", fx->path_dir);
    write_exec(path);
    snprintf(fx->identity, sizeof fx->identity, "%s/id_demo", fx->root);
    write_exec(fx->identity);

    if (setenv("XDG_STATE_HOME", fx->state_root, 1) != 0) {
        perror("setenv");
        exit(1);
    }
    {
        const char *old = getenv("PATH");

        snprintf(fx->old_path, sizeof fx->old_path, "%s", old != NULL ? old : "");
        snprintf(path, sizeof path, "%s:%s", fx->path_dir, fx->old_path);
        if (setenv("PATH", path, 1) != 0) {
            perror("setenv");
            exit(1);
        }
    }
    if (state_open("demo", "us-east-1", &fx->state) != 0) {
        fprintf(stderr, "state_open failed\n");
        exit(1);
    }
}

/* Isolate scenarios: a fresh binding map + known-hosts store per scenario. */
static void reset_store(fixture *fx) {
    (void)unlink(state_known_hosts_path(fx->state));
    (void)unlink(state_bindings_path(fx->state));
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

static void fixture_done(fixture *fx) {
    state_close(fx->state);
    (void)setenv("PATH", fx->old_path, 1);
    remove_tree(fx->root);
}

static void config_init(instance_config *cfg, const fixture *fx, int ddns_onbox) {
    memset(cfg, 0, sizeof *cfg);
    snprintf(cfg->project, sizeof cfg->project, "%s", "demo");
    snprintf(cfg->region, sizeof cfg->region, "%s", "us-east-1");
    snprintf(cfg->arch, sizeof cfg->arch, "%s", "amd64");
    cfg->spot_default = 0;
    snprintf(cfg->ami_policy, sizeof cfg->ami_policy, "%s", "pinned");
    snprintf(cfg->ami_id_amd64, sizeof cfg->ami_id_amd64, "%s",
             "ami-0123456789abcdef0");
    snprintf(cfg->instance_types_amd64, sizeof cfg->instance_types_amd64, "%s",
             "g4dn.xlarge,m5.large");
    cfg->root_volume_size_gb = 100;
    snprintf(cfg->root_volume_type, sizeof cfg->root_volume_type, "%s", "gp3");
    snprintf(cfg->key_name, sizeof cfg->key_name, "%s", "demo-key");
    snprintf(cfg->ssh_identity, sizeof cfg->ssh_identity, "%s", fx->identity);
    snprintf(cfg->ssh_user, sizeof cfg->ssh_user, "%s", "ec2-user");
    cfg->ssh_port = 22;
    snprintf(cfg->operator_cidr, sizeof cfg->operator_cidr, "%s",
             "203.0.113.0/24");
    snprintf(cfg->service_unit, sizeof cfg->service_unit, "%s",
             "demo.service");
    snprintf(cfg->setup_entrypoint, sizeof cfg->setup_entrypoint, "%s",
             "deploy.sh");
    snprintf(cfg->ddns_host, sizeof cfg->ddns_host, "%s", "app");
    snprintf(cfg->ddns_domain, sizeof cfg->ddns_domain, "%s", "example.com");
    cfg->ddns_onbox = ddns_onbox;
    snprintf(cfg->bucket_modules, sizeof cfg->bucket_modules, "%s", "artifact");
    snprintf(cfg->ip_echo_url, sizeof cfg->ip_echo_url, "%s",
             "https://checkip.example");
}

static void services_init(instance_services *svc) {
    memset(svc, 0, sizeof *svc);
    svc->ec2_run_instances = fake_run_instances;
    svc->ec2_describe_instances = fake_describe_instances;
    svc->ec2_describe_images = fake_describe_images;
    svc->ec2_terminate_instances = fake_terminate;
    svc->ec2_wait_running = fake_wait_running;
    svc->ec2_wait_terminated = fake_wait_terminated;
    svc->ec2_get_console_output = fake_console;
    svc->cfn_describe_stacks = fake_describe_stacks;
    svc->ssm_get_parameter = fake_ssm;
    svc->s3_head_object = fake_s3_head;
    svc->s3_get_object = fake_s3_get;
    svc->dns_a_record = fake_dns;
    svc->dns_record_exists = fake_dns_exists;
    svc->ddns_update = fake_ddns;
    svc->ddns_ip_echo = fake_ip_echo;
    svc->keyscan = fake_keyscan;
    svc->ssh_exec = fake_ssh_exec;
    svc->kh_pin = kh_pin;
    svc->kh_bound = kh_bound;
    svc->kh_forget = kh_forget;
    svc->iam_get_caller_identity = fake_identity;
}

static void runtime_init(instance_runtime *rt, const instance_config *cfg,
                         fixture *fx, FILE *out) {
    instance_services svc;

    services_init(&svc);
    instance_runtime_init(rt, cfg, fx->state, &svc, 0, 1, 0);
    rt->dns_attempts = 1;
    rt->dns_interval = 0;
    rt->wait_attempts = 1;
    rt->wait_interval = 0;
    rt->ssh_attempts = 1;
    rt->ssh_interval = 0;
    rt->out = out != NULL ? out : tmpfile();
    rt->err = tmpfile();
}

static char *read_stream(FILE *stream) {
    long size;
    char *buffer;

    if (fflush(stream) != 0 || fseek(stream, 0, SEEK_END) != 0) {
        return NULL;
    }
    size = ftell(stream);
    if (size < 0 || fseek(stream, 0, SEEK_SET) != 0) {
        return NULL;
    }
    buffer = calloc((size_t)size + 1, 1);
    if (buffer == NULL) {
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, stream) != (size_t)size) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

/* ------------------------------------------------------------------------- */
/* Scenarios                                                                 */
/* ------------------------------------------------------------------------- */

static void scenario_launch_and_contract(fixture *fx) {
    instance_config cfg;
    instance_runtime rt;
    launch_options opts;

    world_reset();
    reset_store(fx);
    world_add("i-old", "running", "198.51.100.10", "oldnonce");
    set_manifest(&W, AMBIGUOUS_MANIFEST);
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "198.51.100.10");
    config_init(&cfg, fx, 0);
    runtime_init(&rt, &cfg, fx, NULL);
    memset(&opts, 0, sizeof opts);
    opts.spot_set = -1;
    opts.instance_timeout = 1;
    opts.ssh_timeout = 1;
    opts.setup_timeout = 1;

    /* Ambiguous amd64 manifest member without --variant -> exit 1. */
    CHECK(launch_execute(&rt, &opts) == CLI_EXIT_USAGE,
          "ambiguous member selection is usage error");
    CHECK(W.ddns_calls == 0, "no DNS update before member selection");

    /* Explicit --variant go succeeds and replaces the old instance. */
    opts.variant = "go";
    int rc = launch_execute(&rt, &opts);
    CHECK(rc == CLI_EXIT_OK, "launch succeeds with explicit variant");
    CHECK(strcmp(W.last_run_nonce, "") != 0, "launch nonce generated");
    CHECK(strlen(W.last_run_client_token) == 64, "ClientToken is sha256 hex");
    CHECK(strcmp(W.dns_ip, "203.0.113.20") == 0, "DDNS updated to new IP");
    CHECK(W.ddns_calls == 1, "one DDNS update");
    CHECK(W.last_terminated_count == 1 &&
              strcmp(W.last_terminated[0], "i-old") == 0,
          "previous instance replaced");
    CHECK(kh_bound(state_known_hosts_path(fx->state), "i-new"),
          "known-hosts binding written for new instance");
    CHECK(!kh_bound(state_known_hosts_path(fx->state), "i-old"),
          "old binding forgotten");
    CHECK(W.console_calls > 0, "console fingerprints polled");
    CHECK(W.keyscan_calls > 0, "ssh-keyscan used");
    CHECK(strstr(W.last_ssh_command, "HostKeyAlias=i-new") != NULL,
          "ssh targets instance-id alias");
    CHECK(strstr(W.last_ssh_command, "StrictHostKeyChecking=yes") != NULL,
          "strict host-key checking after verification");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_PROJECT='demo'") != NULL,
          "env contract: project");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_REGION='us-east-1'") != NULL,
          "env contract: region");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_RELEASE_TAG='v1.2.3'") != NULL,
          "env contract: release tag");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_MANIFEST_SHA='") != NULL,
          "env contract: manifest sha");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_ARCH='amd64'") != NULL,
          "env contract: arch");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_VARIANT='go'") != NULL,
          "env contract: variant");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_BUCKET_ARTIFACT='") != NULL,
          "env contract: artifact bucket");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_DDNS_PASSWORD_FILE") == NULL,
          "env contract: no DDNS secret when DDNS_ONBOX=false");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_MEMBER_SHA='") != NULL,
          "env contract: member sha passed to box");

    /* Launch record appended under the nonce (status orphan detection). */
    {
        FILE *file = fopen(state_launch_records_path(fx->state), "r");
        char line[1024];
        char nonce[STATE_NONCE_MAX] = {0};
        int found = 0;

        snprintf(nonce, sizeof nonce, "%s", W.last_run_nonce);
        while (file != NULL && fgets(line, sizeof line, file) != NULL) {
            if (strstr(line, nonce) != NULL) {
                found = 1;
            }
        }
        if (file != NULL) {
            fclose(file);
        }
        CHECK(found, "launch record contains the nonce");
    }

    fclose(rt.out);
    fclose(rt.err);
}

static void scenario_ddns_onbox_env(fixture *fx) {
    instance_config cfg;
    instance_runtime rt;
    launch_options opts;

    world_reset();
    reset_store(fx);
    world_add("i-old", "running", "198.51.100.10", "oldnonce");
    set_manifest(&W, AMBIGUOUS_MANIFEST);
    config_init(&cfg, fx, 1); /* DDNS_ONBOX=true */
    runtime_init(&rt, &cfg, fx, NULL);
    memset(&opts, 0, sizeof opts);
    opts.spot_set = -1;
    opts.variant = "go";

    CHECK(launch_execute(&rt, &opts) == CLI_EXIT_OK,
          "launch with DDNS_ONBOX");
    CHECK(strstr(W.last_ssh_command, "STACKCTL_DDNS_PASSWORD_FILE='") != NULL,
          "env contract: password file iff DDNS_ONBOX=true");

    fclose(rt.out);
    fclose(rt.err);
}

static void scenario_status_json(fixture *fx) {
    instance_config cfg;
    instance_runtime rt;
    status_options opts = {0};
    FILE *out;

    world_reset();
    reset_store(fx);
    world_add("i-live", "running", "203.0.113.20", "nonce-1");
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "203.0.113.20");
    config_init(&cfg, fx, 0);
    out = tmpfile();
    if (out == NULL) {
        CHECK(0, "status output stream opens");
        return;
    }
    runtime_init(&rt, &cfg, fx, out);
    rt.json = 1;

    int rc = status_execute(&rt, &opts);
    CHECK(rc == CLI_EXIT_OK, "status exits 0 with warnings only");

    char *json = read_stream(out);
    CHECK(json != NULL, "status wrote JSON");
    if (json != NULL) {
        yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
        CHECK(doc != NULL, "status JSON parses");
        if (doc != NULL) {
            yyjson_val *root = yyjson_doc_get_root(doc);
            yyjson_val *version = yyjson_obj_get(root, "schema_version");
            yyjson_val *verb = yyjson_obj_get(root, "verb");
            yyjson_val *instances = yyjson_obj_get(root, "instances");

            CHECK(version != NULL && yyjson_is_uint(version) &&
                      yyjson_get_uint(version) == 1,
                  "schema_version is 1");
            CHECK(verb != NULL && strcmp(yyjson_get_str(verb), "status") == 0,
                  "verb is status");
            CHECK(instances != NULL && yyjson_is_arr(instances),
                  "instances is an array");
            CHECK(strstr(json, "ddns-secret") == NULL,
                  "status JSON never contains the DDNS secret");
            CHECK(strstr(json, "i-live") != NULL, "live instance reported");
            yyjson_doc_free(doc);
        }
        free(json);
    }

    /* Identity mismatch is exit 3 (verification failure). */
    W.identity_ok = 0;
    fseek(out, 0, SEEK_SET);
    {
        int mismatch = status_execute(&rt, &opts);
        CHECK(mismatch == CLI_EXIT_VERIFY, "identity guard exit 3");
    }
    W.identity_ok = 1;

    fclose(out); /* rt.out aliases `out` */
    fclose(rt.err);
}

static void scenario_start_stop(fixture *fx) {
    instance_config cfg;
    instance_runtime rt;
    startstop_options opts = {0};

    world_reset();
    reset_store(fx);
    world_add("i-live", "running", "203.0.113.20", "nonce-1");
    config_init(&cfg, fx, 0);
    runtime_init(&rt, &cfg, fx, NULL);

    /* Fresh store: the pin must succeed and the binding must then exist. */
    CHECK(kh_pin(state_known_hosts_path(fx->state), "i-live",
                 KEY_ONE) == 0 &&
              kh_bound(state_known_hosts_path(fx->state), "i-live"),
          "host key pinned and bound for start/stop");

    CHECK(startstop_execute(&rt, &opts, STARTSTOP_START) == CLI_EXIT_OK,
          "start succeeds");
    CHECK(strstr(W.last_ssh_command, "systemctl start demo.service") != NULL,
          "start runs the configured unit");

    CHECK(startstop_execute(&rt, &opts, STARTSTOP_STOP) == CLI_EXIT_OK,
          "stop succeeds");
    CHECK(strstr(W.last_ssh_command, "systemctl stop demo.service") != NULL,
          "stop runs the configured unit");

    /* Two running instances -> ambiguous, exit 1, no ssh. */
    world_add("i-other", "running", "203.0.113.21", "nonce-2");
    int before = W.ssh_calls;
    CHECK(startstop_execute(&rt, &opts, STARTSTOP_START) == CLI_EXIT_USAGE,
          "multiple running instances is usage error");
    CHECK(W.ssh_calls == before, "ambiguous target performs no ssh");

    /* Explicit --instance-id resolves the ambiguity. */
    opts.instance_id = "i-live";
    CHECK(startstop_execute(&rt, &opts, STARTSTOP_START) == CLI_EXIT_OK,
          "--instance-id selects one target");

    /* No binding -> re-verify via console + keyscan, then bind. */
    world_remove_terminated();
    W.instance_count = 1;
    opts.instance_id = NULL;
    CHECK(kh_forget(state_known_hosts_path(fx->state), "i-live") == 0,
          "binding cleared");
    CHECK(startstop_execute(&rt, &opts, STARTSTOP_STOP) == CLI_EXIT_OK,
          "missing binding re-verifies and binds");
    CHECK(kh_bound(state_known_hosts_path(fx->state), "i-live"),
          "binding restored after re-verification");

    /* No binding + no console fingerprints -> exit 7, never silent TOFU. */
    CHECK(kh_forget(state_known_hosts_path(fx->state), "i-live") == 0,
          "binding cleared again");
    W.console_has_fingerprints = 0;
    CHECK(startstop_execute(&rt, &opts, STARTSTOP_STOP) == CLI_EXIT_SSH,
          "unverifiable host key is exit 7");

    fclose(rt.out);
    fclose(rt.err);
}

static void scenario_terminate(fixture *fx) {
    instance_config cfg;
    instance_runtime rt;
    terminate_options opts = {0};

    world_reset();
    reset_store(fx);
    world_add("i-a", "running", "203.0.113.20", "n1");
    world_add("i-b", "stopped", "203.0.113.21", "n2");
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "203.0.113.20");
    config_init(&cfg, fx, 0);
    runtime_init(&rt, &cfg, fx, NULL);

    CHECK(terminate_execute(&rt, &opts) == CLI_EXIT_OK, "terminate sweep");
    CHECK(W.last_terminated_count == 2, "sweep terminated every live instance");
    CHECK(strcmp(W.dns_ip, "0.0.0.0") == 0, "DDNS record parked");
    CHECK(!kh_bound(state_known_hosts_path(fx->state), "i-a"),
          "bindings forgotten");

    /* Zero matches still parks the record (spot-interruption cleanup). */
    W.instance_count = 0;
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "203.0.113.99");
    CHECK(terminate_execute(&rt, &opts) == CLI_EXIT_OK,
          "zero-match sweep succeeds");
    CHECK(strcmp(W.dns_ip, "0.0.0.0") == 0,
          "zero-match sweep still parks the record");

    /* --instance-id that is not Project-tagged is usage (exit 1). */
    W.instance_count = 0;
    {
        ec2_instance *foreign = world_add("i-foreign", "running", "203.0.113.30",
                                          "n3");
        snprintf(foreign->tags[0].value, sizeof foreign->tags[0].value, "%s",
                 "other");
    }
    opts.instance_id = "i-foreign";
    W.terminate_confirmed = 0;
    CHECK(terminate_execute(&rt, &opts) == CLI_EXIT_USAGE,
          "untagged --instance-id is refused");
    CHECK(W.terminate_confirmed == 0, "no termination issued for refused id");

    /* --instance-id parks only when the record points at that instance. */
    W.instance_count = 0;
    world_add("i-target", "running", "203.0.113.40", "n4");
    opts.instance_id = "i-target";
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "203.0.113.41");
    CHECK(terminate_execute(&rt, &opts) == CLI_EXIT_OK,
          "targeted terminate succeeds");
    CHECK(strcmp(W.dns_ip, "0.0.0.0") != 0,
          "targeted terminate leaves an unrelated DNS record");

    /* A waiter timeout is exit 5 and skips the park. */
    W.instance_count = 0;
    world_add("i-slow", "running", "203.0.113.50", "n5");
    opts.instance_id = NULL;
    snprintf(W.dns_ip, sizeof W.dns_ip, "%s", "203.0.113.50");
    W.terminate_wait_timed_out = 1;
    CHECK(terminate_execute(&rt, &opts) == CLI_EXIT_CLEANUP,
          "termination waiter timeout is exit 5");
    CHECK(strcmp(W.dns_ip, "203.0.113.50") == 0,
          "park skipped after waiter timeout");

    fclose(rt.out);
    fclose(rt.err);
}

static void scenario_launch_failures(fixture *fx) {
    instance_config cfg;
    instance_runtime rt;
    launch_options opts;

    /* Missing SSM DDNS parameter -> exit 1 before any spend. */
    world_reset();
    reset_store(fx);
    world_add("i-old", "running", "198.51.100.10", "oldnonce");
    set_manifest(&W, AMBIGUOUS_MANIFEST);
    config_init(&cfg, fx, 0);
    runtime_init(&rt, &cfg, fx, NULL);
    memset(&opts, 0, sizeof opts);
    opts.spot_set = -1;
    opts.variant = "go";
    W.dns_record_exists = 0;
    CHECK(launch_execute(&rt, &opts) == CLI_EXIT_USAGE,
          "missing DDNS record is exit 1");
    CHECK(W.last_terminated_count == 0, "preflight failure touches no instance");

    /* RunInstances capacity failure -> exit 2, old instance untouched. */
    world_reset();
    reset_store(fx);
    world_add("i-old", "running", "198.51.100.10", "oldnonce");
    set_manifest(&W, AMBIGUOUS_MANIFEST);
    runtime_init(&rt, &cfg, fx, NULL);
    W.run_fail = 1;
    CHECK(launch_execute(&rt, &opts) == CLI_EXIT_AWS,
          "RunInstances failure is exit 2");
    CHECK(W.instance_count == 1, "old instance untouched on AWS failure");

    fclose(rt.out);
    fclose(rt.err);
}

int main(void) {
    fixture fx;

    fixture_init(&fx);
    scenario_launch_and_contract(&fx);
    scenario_ddns_onbox_env(&fx);
    scenario_status_json(&fx);
    scenario_start_stop(&fx);
    scenario_terminate(&fx);
    scenario_launch_failures(&fx);
    fixture_done(&fx);

    if (failures != 0) {
        fprintf(stderr, "%d lifecycle test(s) failed\n", failures);
        return 1;
    }
    printf("lifecycle_test: ok\n");
    return 0;
}
