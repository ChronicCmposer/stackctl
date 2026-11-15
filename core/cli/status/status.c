/*
 * status.c — `stackctl status` (spec §4). Read-only and lockless.
 *
 * Reports preflight prerequisites, the infra stack and its key parameters, the
 * Project-tagged instances plus the AMI each was launched from, DDNS state vs
 * actual instance IPs, the pinned release, known-hosts bindings, and warnings
 * (operator CIDR, orphans, release health, multi-writer). Exit 0 = healthy or
 * warnings only; 1 = preflight failure; 2 = AWS error; 3 = identity guard.
 */

#include "status_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "yyjson.h"

#define STATUS_MAX_WARNINGS 32
#define STATUS_WARNING_LEN 256
#define STATUS_MAX_BINDINGS 16
#define STATUS_MAX_MEMBERS 32
#define STATUS_MAX_GARBAGE 16
#define STATUS_MEMBER_NAME_MAX 256
#define STATUS_PREFIX_LEN 128

typedef struct status_binding {
    char instance_id[STATE_INSTANCE_ID_MAX];
    char fqdn[STATE_FQDN_MAX];
    char ip[STATE_IP_MAX];
    char host_key[STATE_HOST_KEY_MAX];
} status_binding;

typedef struct status_member {
    char name[STATUS_MEMBER_NAME_MAX];
    char sha[INST_SHA_MAX];
    int present; /* 1 present, 0 missing, -1 unknown */
} status_member;

typedef struct status_report {
    char warnings[STATUS_MAX_WARNINGS][STATUS_WARNING_LEN];
    size_t warning_count;
    status_binding bindings[STATUS_MAX_BINDINGS];
    size_t binding_count;
    status_member members[STATUS_MAX_MEMBERS];
    size_t member_count;
    char garbage[STATUS_MAX_GARBAGE][STATUS_PREFIX_LEN];
    size_t garbage_count;
} status_report;

static void add_warning(status_report *report, const char *fmt, ...) {
    va_list args;

    if (report->warning_count >= STATUS_MAX_WARNINGS) {
        return;
    }
    va_start(args, fmt);
    vsnprintf(report->warnings[report->warning_count], STATUS_WARNING_LEN, fmt,
              args);
    va_end(args);
    report->warning_count++;
}

/* Scan PATH for an executable named `name` (operator-workstation prereq). */
static int tool_present(const char *name) {
    const char *path = getenv("PATH");
    char *copy;
    char *save = NULL;
    char *token;
    int found = 0;

    if (path == NULL || name == NULL) {
        return 0;
    }
    copy = strdup(path);
    if (copy == NULL) {
        return 0;
    }
    for (token = strtok_r(copy, ":", &save); token != NULL;
         token = strtok_r(NULL, ":", &save)) {
        char candidate[1024];

        if (snprintf(candidate, sizeof candidate, "%s/%s", token, name) < 0) {
            continue;
        }
        if (access(candidate, X_OK) == 0) {
            found = 1;
            break;
        }
    }
    free(copy);
    return found;
}

/* IPv4 helpers for the operator-CIDR containment warning. */
static int parse_ipv4(const char *text, unsigned long *out) {
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    char tail;

    if (sscanf(text, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) {
        return EINVAL;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return EINVAL;
    }
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

static int cidr_contains(const char *cidr, const char *ip) {
    char base[64];
    const char *slash;
    unsigned long network;
    unsigned long address;
    long prefix;
    unsigned long mask;

    if (cidr == NULL || ip == NULL) {
        return 0;
    }
    slash = strchr(cidr, '/');
    if (slash == NULL || (size_t)(slash - cidr) >= sizeof base) {
        return 0;
    }
    memcpy(base, cidr, (size_t)(slash - cidr));
    base[slash - cidr] = '\0';
    prefix = strtol(slash + 1, NULL, 10);
    if (prefix < 0 || prefix > 32) {
        return 0;
    }
    if (parse_ipv4(base, &network) != 0 || parse_ipv4(ip, &address) != 0) {
        return 0;
    }
    mask = prefix == 0 ? 0 : (0xffffffffu << (32 - (unsigned)prefix));
    return (network & mask) == (address & mask);
}

/* True when `nonce` appears in the launch-records log (state available). */
static int nonce_recorded(instance_runtime *rt, const char *nonce) {
    FILE *file;
    char line[1024];
    int found = 0;

    if (rt->state == NULL || nonce == NULL || nonce[0] == '\0') {
        return 0;
    }
    file = fopen(state_launch_records_path(rt->state), "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof line, file) != NULL) {
        char *fields[3];
        int count = 0;
        char *save = NULL;
        char *token = strtok_r(line, "\t\n", &save);

        while (token != NULL && count < 3) {
            fields[count++] = token;
            token = strtok_r(NULL, "\t\n", &save);
        }
        if (count == 3 && strcmp(fields[2], nonce) == 0) {
            found = 1;
            break;
        }
    }
    fclose(file);
    return found;
}

static const char *effective_ami(instance_runtime *rt, const cfn_stack *stack,
                                 const char *arch, char *buffer, size_t cap,
                                 status_report *report) {
    const char *policy = rt->cfg.ami_policy;

    (void)report;
    const char *stack_key =
        strcmp(arch, "arm64") == 0 ? "AmiIdArm64" : "AmiIdAmd64";

    if (strcmp(policy, "pinned") == 0) {
        /* Under a pin the stack is the only source; config is not a fallback. */
        const char *value =
            stack != NULL ? cfn_stack_parameter(stack, stack_key) : NULL;

        snprintf(buffer, cap, "%s", value != NULL ? value : "");
        return buffer;
    }
    {
        char name[INST_SSM_PARAM_MAX];
        ssm_parameter parameter;
        int rc;

        if (strcmp(policy, "baked") == 0) {
            snprintf(name, sizeof name, "/%s/ami/baked/latest",
                     rt->cfg.project);
        } else {
            snprintf(name, sizeof name, "%s",
                     strcmp(arch, "arm64") == 0 ? rt->cfg.ami_ssm_arm64
                                                : rt->cfg.ami_ssm_amd64);
        }
        if (name[0] == '\0') {
            return NULL;
        }
        memset(&parameter, 0, sizeof parameter);
        rc = rt->svc.ssm_get_parameter(rt->svc.ssm, name, 0, &parameter);
        if (rc != 0) {
            return NULL;
        }
        snprintf(buffer, cap, "%s",
                 parameter.value != NULL ? parameter.value : "");
        ssm_parameter_free(&parameter);
        return buffer;
    }
}

static int ami_preflight(instance_runtime *rt, const cfn_stack *stack,
                         status_report *report) {
    const char *archs[2];
    size_t arch_count = 0;

    if (strcmp(rt->cfg.arch, "both") == 0) {
        archs[arch_count++] = "amd64";
        archs[arch_count++] = "arm64";
    } else if (rt->cfg.arch[0] != '\0') {
        archs[arch_count++] = rt->cfg.arch;
    }
    for (size_t i = 0; i < arch_count; i++) {
        char ami[INST_AMI_ID_MAX];
        const char *id =
            effective_ami(rt, stack, archs[i], ami, sizeof ami, report);
        ec2_image_list images;
        int rc;

        if (id == NULL || id[0] == '\0') {
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "no effective AMI for %s in %s", archs[i],
                                 rt->cfg.region);
        }
        if (rt->svc.ec2_describe_images == NULL) {
            continue;
        }
        memset(&images, 0, sizeof images);
        rc = rt->svc.ec2_describe_images(rt->svc.ec2, &id, 1, &images);
        if (rc != 0) {
            ec2_image_list_free(&images);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot resolve AMI %s in %s", id,
                                 rt->cfg.region);
        }
        if (images.count == 0) {
            ec2_image_list_free(&images);
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "AMI %s does not exist in %s", id,
                                 rt->cfg.region);
        }
        ec2_image_list_free(&images);
    }
    return CLI_EXIT_OK;
}

/* STS identity guard: the caller ARN must end in `:user/<project>` (exit 3). */
static int identity_guard(instance_runtime *rt) {
    char *arn = NULL;
    char suffix[INST_PROJECT_MAX + 16];
    size_t arn_len;
    size_t suffix_len;
    int rc;

    if (rt->svc.iam_get_caller_identity == NULL) {
        return CLI_EXIT_OK;
    }
    rc = rt->svc.iam_get_caller_identity(rt->svc.aws, NULL, &arn, NULL);
    if (rc != 0) {
        free(arn);
        return instance_fail(rt, CLI_EXIT_AWS,
                             "cannot verify the caller identity");
    }
    if (arn == NULL) {
        return instance_fail(rt, CLI_EXIT_VERIFY,
                             "identity guard: no caller ARN returned");
    }
    snprintf(suffix, sizeof suffix, ":user/%s", rt->cfg.project);
    arn_len = strlen(arn);
    suffix_len = strlen(suffix);
    if (arn_len < suffix_len ||
        strcmp(arn + (arn_len - suffix_len), suffix) != 0) {
        rc = instance_fail(rt, CLI_EXIT_VERIFY,
                           "identity guard: %s does not end with %s", arn,
                           suffix);
    } else {
        rc = CLI_EXIT_OK;
    }
    free(arn);
    return rc;
}

/* Read the dedicated binding map (tab-separated) for reporting. */
static void load_bindings(instance_runtime *rt, status_report *report) {
    FILE *file;
    char line[2048];

    if (rt->state == NULL) {
        return;
    }
    file = fopen(state_bindings_path(rt->state), "r");
    if (file == NULL) {
        return;
    }
    while (fgets(line, sizeof line, file) != NULL &&
           report->binding_count < STATUS_MAX_BINDINGS) {
        char *fields[5];
        int count = 0;
        char *save = NULL;
        char *token;

        line[strcspn(line, "\n")] = '\0';
        token = strtok_r(line, "\t", &save);
        while (token != NULL && count < 5) {
            fields[count++] = token;
            token = strtok_r(NULL, "\t", &save);
        }
        if (count < 4) {
            continue;
        }
        status_binding *binding = &report->bindings[report->binding_count++];

        snprintf(binding->instance_id, sizeof binding->instance_id, "%s",
                 fields[0]);
        snprintf(binding->host_key, sizeof binding->host_key, "%s", fields[1]);
        snprintf(binding->fqdn, sizeof binding->fqdn, "%s", fields[2]);
        snprintf(binding->ip, sizeof binding->ip, "%s", fields[3]);
    }
    fclose(file);
}

/* List the pinned release's manifest members and manifest-less prefixes. */
static void release_health(instance_runtime *rt, const cfn_stack *stack,
                           status_report *report) {
    char key[512];
    char *manifest = NULL;
    size_t len = 0;
    const char *tag;
    const char *bucket;
    int rc;

    if (stack == NULL) {
        return;
    }
    tag = cfn_stack_tag(stack, "stackctl:release-tag");
    bucket = cfn_stack_output(stack, "ArtifactBucketName");
    if (tag == NULL || tag[0] == '\0' || bucket == NULL || bucket[0] == '\0') {
        return;
    }
    if (snprintf(key, sizeof key, "releases/%s/release-manifest.txt", tag) >=
        (int)sizeof key) {
        return;
    }

    if (rt->svc.s3_get_object != NULL) {
        rc = rt->svc.s3_get_object(rt->svc.s3, bucket, key, &manifest, &len);
        if (rc == ENOENT) {
            add_warning(report,
                        "release manifest for %s is missing from bucket %s",
                        tag, bucket);
        } else if (rc == 0 && manifest != NULL) {
            const char *line = manifest;

            while (*line != '\0' &&
                   report->member_count < STATUS_MAX_MEMBERS) {
                char copy[1024];
                const char *newline = strchr(line, '\n');
                size_t line_len =
                    newline != NULL ? (size_t)(newline - line) : strlen(line);
                char *save = NULL;
                char *sha;
                char *name;

                if (line_len >= sizeof copy) {
                    break;
                }
                memcpy(copy, line, line_len);
                copy[line_len] = '\0';
                sha = strtok_r(copy, " \t\r", &save);
                name = strtok_r(NULL, " \t\r", &save);
                if (sha != NULL && name != NULL) {
                    status_member *member =
                        &report->members[report->member_count++];

                    snprintf(member->name, sizeof member->name, "%s", name);
                    snprintf(member->sha, sizeof member->sha, "%s", sha);
                    member->present = -1;
                    if (rt->svc.s3_head_object != NULL) {
                        char member_key[768];
                        unsigned long long size = 0;
                        char etag[S3_ETAG_MAX];
                        int head_rc;

                        snprintf(member_key, sizeof member_key,
                                 "releases/%s/%s", tag, name);
                        head_rc = rt->svc.s3_head_object(
                            rt->svc.s3, bucket, member_key, &size, etag);
                        if (head_rc == ENOENT) {
                            member->present = 0;
                            add_warning(report,
                                        "release member %s is missing from "
                                        "bucket %s",
                                        name, bucket);
                        } else if (head_rc == 0) {
                            member->present = 1;
                        }
                    }
                }
                if (newline == NULL) {
                    break;
                }
                line = newline + 1;
            }
        }
        free(manifest);
    }

    if (rt->svc.s3_list_objects != NULL) {
        s3_object_list list;
        char prefixes[STATUS_MAX_GARBAGE][STATUS_PREFIX_LEN];
        size_t prefix_count = 0;

        memset(&list, 0, sizeof list);
        if (rt->svc.s3_list_objects(rt->svc.s3, bucket, "releases/", &list) ==
            0) {
            for (size_t i = 0; i < list.count; i++) {
                const char *object = list.items[i].key;
                const char *slash;

                if (object == NULL || strncmp(object, "releases/", 9) != 0) {
                    continue;
                }
                slash = strchr(object + 9, '/');
                if (slash == NULL ||
                    (size_t)(slash - object) + 1 >= STATUS_PREFIX_LEN) {
                    continue;
                }
                {
                    size_t prefix_len = (size_t)(slash - object) + 1;
                    int seen = 0;

                    for (size_t p = 0; p < prefix_count; p++) {
                        if (strncmp(prefixes[p], object, prefix_len) == 0 &&
                            prefixes[p][prefix_len] == '\0') {
                            seen = 1;
                        }
                    }
                    if (!seen) {
                        memcpy(prefixes[prefix_count], object, prefix_len);
                        prefixes[prefix_count][prefix_len] = '\0';
                        prefix_count++;
                    }
                }
            }
            for (size_t p = 0; p < prefix_count; p++) {
                char manifest_key[STATUS_PREFIX_LEN + 32];
                int has_manifest = 0;

                snprintf(manifest_key, sizeof manifest_key,
                         "%srelease-manifest.txt", prefixes[p]);
                for (size_t i = 0; i < list.count; i++) {
                    if (list.items[i].key != NULL &&
                        strcmp(list.items[i].key, manifest_key) == 0) {
                        has_manifest = 1;
                    }
                }
                if (!has_manifest &&
                    report->garbage_count < STATUS_MAX_GARBAGE) {
                    snprintf(report->garbage[report->garbage_count],
                             STATUS_PREFIX_LEN, "%s", prefixes[p]);
                    report->garbage_count++;
                    add_warning(report,
                                "garbage prefix %s has no release manifest",
                                prefixes[p]);
                }
            }
        }
        s3_object_list_free(&list);
    }
}

static void check_prerequisites(instance_runtime *rt, status_report *report,
                                int *fatal) {
    *fatal = 0;
    if (rt->cfg.key_name[0] == '\0') {
        instance_fail(rt, CLI_EXIT_USAGE, "missing KEY_NAME in config");
        *fatal = 1;
        return;
    }
    if (rt->cfg.ssh_identity[0] == '\0' ||
        access(rt->cfg.ssh_identity, R_OK) != 0) {
        instance_fail(rt, CLI_EXIT_USAGE,
                      "SSH_IDENTITY is missing or unreadable: %s",
                      rt->cfg.ssh_identity);
        *fatal = 1;
        return;
    }
    if (!tool_present("ssh") || !tool_present("scp")) {
        instance_fail(rt, CLI_EXIT_USAGE, "ssh/scp not found on PATH");
        *fatal = 1;
        return;
    }
    if (!tool_present("ssh-keyscan")) {
        add_warning(report, "ssh-keyscan not found on PATH (launch cannot pin "
                            "host keys)");
    }
    if (rt->state != NULL) {
        const char *dir = state_dir(rt->state);

        if (dir == NULL || access(dir, W_OK) != 0) {
            instance_fail(rt, CLI_EXIT_USAGE, "state directory is not writable");
            *fatal = 1;
            return;
        }
    }
    if (rt->cfg.operator_cidr[0] == '\0') {
        add_warning(report,
                    "OPERATOR_CIDR is empty; SSH is impossible (set it and "
                    "redeploy)");
    }
}

static void json_report(instance_runtime *rt, const cfn_stack *stack,
                        const ec2_instance_list *instances,
                        const char *record_ip, int record_present,
                        const status_report *report) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root;

    if (doc == NULL) {
        return;
    }
    root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_uint(doc, root, "schema_version", 1);
    yyjson_mut_obj_add_str(doc, root, "verb", "status");
    yyjson_mut_obj_add_str(doc, root, "project", rt->cfg.project);
    yyjson_mut_obj_add_str(doc, root, "region", rt->cfg.region);

    if (stack != NULL) {
        yyjson_mut_val *node = yyjson_mut_obj(doc);

        yyjson_mut_obj_add_str(doc, node, "name", stack->stack_name);
        yyjson_mut_obj_add_str(doc, node, "status",
                               cfn_stack_status_string(stack->status));
        yyjson_mut_obj_add_val(doc, root, "stack", node);
    } else {
        yyjson_mut_obj_add_val(doc, root, "stack", yyjson_mut_null(doc));
    }

    {
        yyjson_mut_val *arr = yyjson_mut_arr(doc);

        for (size_t i = 0; i < instances->count; i++) {
            const ec2_instance *item = &instances->items[i];
            const char *nonce = ec2_instance_tag(item, "stackctl:launch-nonce");
            yyjson_mut_val *node = yyjson_mut_obj(doc);

            yyjson_mut_obj_add_str(doc, node, "id", item->instance_id);
            yyjson_mut_obj_add_str(doc, node, "state", item->state);
            yyjson_mut_obj_add_str(doc, node, "public_ip", item->public_ip);
            yyjson_mut_obj_add_str(doc, node, "ami", item->image_id);
            yyjson_mut_obj_add_str(doc, node, "nonce",
                                   nonce != NULL ? nonce : "");
            yyjson_mut_arr_add_val(arr, node);
        }
        yyjson_mut_obj_add_val(doc, root, "instances", arr);
    }

    if (instance_ddns_configured(rt)) {
        yyjson_mut_val *node = yyjson_mut_obj(doc);

        yyjson_mut_obj_add_str(doc, node, "host", rt->cfg.ddns_host);
        yyjson_mut_obj_add_str(doc, node, "domain", rt->cfg.ddns_domain);
        if (record_present) {
            yyjson_mut_obj_add_str(doc, node, "record_ip", record_ip);
            yyjson_mut_obj_add_bool(doc, node, "parked",
                                    strcmp(record_ip, "0.0.0.0") == 0 ||
                                        strcmp(record_ip, "127.0.0.1") == 0);
        } else {
            yyjson_mut_obj_add_val(doc, node, "record_ip",
                                   yyjson_mut_null(doc));
        }
        yyjson_mut_obj_add_val(doc, root, "ddns", node);
    } else {
        yyjson_mut_obj_add_val(doc, root, "ddns", yyjson_mut_null(doc));
    }

    {
        yyjson_mut_val *node = yyjson_mut_obj(doc);
        const char *tag = stack != NULL
                              ? cfn_stack_tag(stack, "stackctl:release-tag")
                              : NULL;
        const char *sha = stack != NULL
                              ? cfn_stack_tag(stack, "stackctl:release-sha")
                              : NULL;

        yyjson_mut_obj_add_str(doc, node, "tag", tag != NULL ? tag : "");
        yyjson_mut_obj_add_str(doc, node, "sha", sha != NULL ? sha : "");
        {
            yyjson_mut_val *members = yyjson_mut_arr(doc);

            for (size_t i = 0; i < report->member_count; i++) {
                yyjson_mut_val *member = yyjson_mut_obj(doc);

                yyjson_mut_obj_add_str(doc, member, "name",
                                       report->members[i].name);
                yyjson_mut_obj_add_str(doc, member, "sha",
                                       report->members[i].sha);
                if (report->members[i].present == 1) {
                    yyjson_mut_obj_add_bool(doc, member, "present", 1);
                } else if (report->members[i].present == 0) {
                    yyjson_mut_obj_add_bool(doc, member, "present", 0);
                } else {
                    yyjson_mut_obj_add_val(doc, member, "present",
                                           yyjson_mut_null(doc));
                }
                yyjson_mut_arr_add_val(members, member);
            }
            yyjson_mut_obj_add_val(doc, node, "members", members);
        }
        {
            yyjson_mut_val *garbage = yyjson_mut_arr(doc);

            for (size_t i = 0; i < report->garbage_count; i++) {
                yyjson_mut_arr_add_str(doc, garbage, report->garbage[i]);
            }
            yyjson_mut_obj_add_val(doc, node, "garbage_prefixes", garbage);
        }
        yyjson_mut_obj_add_val(doc, root, "release", node);
    }

    {
        yyjson_mut_val *arr = yyjson_mut_arr(doc);

        for (size_t i = 0; i < report->binding_count; i++) {
            yyjson_mut_val *node = yyjson_mut_obj(doc);

            yyjson_mut_obj_add_str(doc, node, "instance_id",
                                   report->bindings[i].instance_id);
            yyjson_mut_obj_add_str(doc, node, "fqdn",
                                   report->bindings[i].fqdn);
            yyjson_mut_obj_add_str(doc, node, "ip", report->bindings[i].ip);
            yyjson_mut_obj_add_str(doc, node, "host_key",
                                   report->bindings[i].host_key);
            yyjson_mut_arr_add_val(arr, node);
        }
        yyjson_mut_obj_add_val(doc, root, "bindings", arr);
    }

    {
        yyjson_mut_val *arr = yyjson_mut_arr(doc);

        for (size_t i = 0; i < report->warning_count; i++) {
            yyjson_mut_arr_add_str(doc, arr, report->warnings[i]);
        }
        yyjson_mut_obj_add_val(doc, root, "warnings", arr);
    }

    (void)cli_json_write(rt->out, doc);
    yyjson_mut_doc_free(doc);
}

static void text_report(instance_runtime *rt, const cfn_stack *stack,
                        const ec2_instance_list *instances,
                        const char *record_ip, int record_present,
                        const status_report *report) {
    instance_out(rt, "project: %s  region: %s\n", rt->cfg.project,
                 rt->cfg.region);
    if (stack != NULL) {
        instance_out(rt, "stack: %s %s\n", stack->stack_name,
                     cfn_stack_status_string(stack->status));
        instance_out(rt, "release: %s\n",
                     cfn_stack_tag(stack, "stackctl:release-tag") != NULL
                         ? cfn_stack_tag(stack, "stackctl:release-tag")
                         : "(none)");
    } else {
        instance_out(rt, "stack: (not deployed)\n");
    }
    for (size_t i = 0; i < instances->count; i++) {
        instance_out(rt, "instance: %s %s %s ami=%s\n",
                     instances->items[i].instance_id,
                     instances->items[i].state,
                     instances->items[i].public_ip,
                     instances->items[i].image_id);
    }
    if (instance_ddns_configured(rt)) {
        instance_out(rt, "ddns: %s.%s -> %s%s\n", rt->cfg.ddns_host,
                     rt->cfg.ddns_domain,
                     record_present ? record_ip : "(missing)",
                     record_present &&
                             (strcmp(record_ip, "0.0.0.0") == 0 ||
                              strcmp(record_ip, "127.0.0.1") == 0)
                         ? " (parked)"
                         : "");
    }
    for (size_t i = 0; i < report->binding_count; i++) {
        instance_out(rt, "binding: %s %s -> %s\n",
                     report->bindings[i].instance_id,
                     report->bindings[i].fqdn, report->bindings[i].ip);
    }
    for (size_t i = 0; i < report->warning_count; i++) {
        instance_warn(rt, "%s", report->warnings[i]);
    }
}

int status_execute(instance_runtime *rt, const status_options *opts) {
    status_report report;
    cfn_stack_list stacks;
    ec2_instance_list instances;
    const cfn_stack *stack = NULL;
    char record_ip[64] = {0};
    int record_present = 0;
    int fatal = 0;
    int rc;

    (void)opts;
    if (rt == NULL) {
        return CLI_EXIT_USAGE;
    }
    memset(&report, 0, sizeof report);
    memset(&stacks, 0, sizeof stacks);
    memset(&instances, 0, sizeof instances);

    check_prerequisites(rt, &report, &fatal);
    if (fatal) {
        return CLI_EXIT_USAGE;
    }

    rc = identity_guard(rt);
    if (rc != CLI_EXIT_OK) {
        return rc;
    }
    load_bindings(rt, &report);

    /* Infra stack (absent is not an error). */
    if (rt->svc.cfn_describe_stacks == NULL) {
        return instance_fail(rt, CLI_EXIT_USAGE, "CloudFormation unavailable");
    }
    {
        char stack_name[INST_PROJECT_MAX + 16];

        snprintf(stack_name, sizeof stack_name, "%s-infra", rt->cfg.project);
        rc = rt->svc.cfn_describe_stacks(rt->svc.cfn, rt->cfg.region,
                                         stack_name, &stacks);
        if (rc == ENOENT) {
            stacks.count = 0;
        } else if (rc != 0) {
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot describe the infra stack");
        }
        if (stacks.count > 0) {
            stack = &stacks.items[0];
        }
    }

    rc = ami_preflight(rt, stack, &report);
    if (rc != CLI_EXIT_OK) {
        cfn_stack_list_free(&stacks);
        return rc;
    }

    if (rt->svc.ec2_describe_instances == NULL) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE, "EC2 unavailable");
    }
    {
        const char *const project_values[] = {rt->cfg.project};
        ec2_filter filter = {"tag:Project", project_values, 1};

        rc = rt->svc.ec2_describe_instances(rt->svc.ec2, &filter, 1,
                                            &instances);
        if (rc != 0) {
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot describe project instances");
        }
    }

    if (instance_ddns_configured(rt)) {
        ssm_parameter parameter;
        char name[INST_SSM_PARAM_MAX];
        bool parked = false;

        snprintf(name, sizeof name, "/%s/ddns/password", rt->cfg.project);
        memset(&parameter, 0, sizeof parameter);
        rc = rt->svc.ssm_get_parameter(rt->svc.ssm, name, 0, &parameter);
        ssm_parameter_free(&parameter);
        if (rc == ENOENT) {
            ec2_instance_list_free(&instances);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "DDNS SSM parameter %s is missing", name);
        }
        if (rc != 0) {
            ec2_instance_list_free(&instances);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot read the DDNS SSM parameter");
        }
        rc = rt->svc.dns_a_record(rt->cfg.ddns_domain, rt->cfg.ddns_host,
                                  record_ip, &parked);
        if (rc == ENOENT) {
            ec2_instance_list_free(&instances);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "DDNS A record %s.%s is missing",
                                 rt->cfg.ddns_host, rt->cfg.ddns_domain);
        }
        if (rc != 0) {
            ec2_instance_list_free(&instances);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot read the DDNS A record");
        }
        record_present = 1;

        {
            int matched = parked;
            const char *recorded_nonce = NULL;

            for (size_t i = 0; i < instances.count; i++) {
                const char *nonce =
                    ec2_instance_tag(&instances.items[i],
                                     "stackctl:launch-nonce");

                if (strcmp(instances.items[i].public_ip, record_ip) == 0 &&
                    instance_state_active(instances.items[i].state)) {
                    matched = 1;
                }
                if (nonce != NULL && nonce[0] != '\0' && !parked) {
                    if (recorded_nonce == NULL) {
                        recorded_nonce = nonce;
                    } else if (strcmp(recorded_nonce, nonce) != 0) {
                        add_warning(&report,
                                    "multiple live launch nonces (multi-writer "
                                    "risk)");
                    }
                }
            }
            if (!matched) {
                add_warning(&report,
                            "DDNS record %s does not match any running "
                            "instance",
                            record_ip);
            }
        }
    }

    /* Orphan detection: a launch nonce with no completed launch record. */
    for (size_t i = 0; i < instances.count; i++) {
        const char *nonce = ec2_instance_tag(&instances.items[i],
                                             "stackctl:launch-nonce");

        if (nonce != NULL && nonce[0] != '\0' &&
            !nonce_recorded(rt, nonce)) {
            add_warning(&report,
                        "orphan instance %s: launch nonce %s has no completed "
                        "launch record",
                        instances.items[i].instance_id, nonce);
        }
    }

    /* Release health: members present and manifest-less garbage prefixes. */
    release_health(rt, stack, &report);

    /* Operator public IP vs OPERATOR_CIDR (warning only). */
    if (rt->cfg.ip_echo_url[0] != '\0' && rt->svc.ddns_ip_echo != NULL &&
        rt->cfg.operator_cidr[0] != '\0') {
        char ip[64] = {0};

        if (rt->svc.ddns_ip_echo(rt->cfg.ip_echo_url, ip) == 0 &&
            !cidr_contains(rt->cfg.operator_cidr, ip)) {
            add_warning(&report,
                        "operator public IP %s is outside OPERATOR_CIDR %s",
                        ip, rt->cfg.operator_cidr);
        }
    }

    if (rt->json) {
        json_report(rt, stack, &instances, record_ip, record_present, &report);
    } else {
        text_report(rt, stack, &instances, record_ip, record_present, &report);
    }

    ec2_instance_list_free(&instances);
    cfn_stack_list_free(&stacks);
    return CLI_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Production entry point (lockless: cli_ctx_init already skipped the lock)   */
/* ------------------------------------------------------------------------- */

int cli_cmd_status(cli_ctx *ctx) {
    instance_services svc;
    instance_runtime rt;
    status_options opts = {0};
    cli_args args;
    int rc;

    if (ctx == NULL) {
        return CLI_EXIT_USAGE;
    }
    rc = cli_ctx_parse_args(ctx, NULL, 0, &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "invalid status arguments");
    }
    rc = instance_services_open(&svc, config_project(cli_ctx_config(ctx)),
                                config_region(cli_ctx_config(ctx)));
    if (rc != 0) {
        cli_args_free(&args);
        return cli_fail(ctx, CLI_EXIT_USAGE, "cannot initialise AWS clients");
    }
    if (instance_runtime_from_ctx(&rt, ctx, &svc) != 0) {
        instance_services_close(&svc);
        cli_args_free(&args);
        return cli_fail(ctx, CLI_EXIT_USAGE, "cannot initialise the runtime");
    }
    rc = status_execute(&rt, &opts);
    instance_services_close(&svc);
    cli_args_free(&args);
    return rc;
}
