/*
 * config.c — stackctl project configuration loader & fail-closed validator.
 *
 * Implements spec §3: flat `.env` / `.env.<region>` selection, region
 * consistency, repo-root resolution, PROJECT regex + per-region S3 bucket-name
 * bound, and the full cross-key validation table. Diagnostics go to stderr;
 * functions return errno-style codes (CONTRACT.md error model).
 */

#include "config.h"

#include "envfile.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* S3 bucket name limit for `<project>-artifacts-<acct>-<region>`:
 * 1 ('-') + 9 ("artifacts") + 1 ('-') + 12 (account) + 1 ('-') = 24. */
#define BUCKET_FIXED_PREFIX_CHARS 24
#define S3_BUCKET_NAME_MAX 63

struct stackctl_config {
    config_envfile *env;
    char *dir;       /* real path of the config directory */
    char *file;      /* real path of the loaded .env file */
    char *repo_root; /* real path of the repo root */
    char *region;    /* resolved region (owned copy) */
    const char *project;
    const char *arch;
    const char *arch_list[3];
    const char *image_builder_parent_image;
    const char *permissions_boundary_arn;
    config_ingress_rule ingress_tcp[CONFIG_INGRESS_MAX];
    size_t ingress_tcp_count;
    config_ingress_rule ingress_udp[CONFIG_INGRESS_MAX];
    size_t ingress_udp_count;
};

/* ------------------------------------------------------------------------- */
/* Diagnostics                                                               */
/* ------------------------------------------------------------------------- */

static int cfg_error(int code, const char *fmt, ...) {
    va_list ap;

    fputs("stackctl: config: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return code;
}

/* ------------------------------------------------------------------------- */
/* Key table and defaults                                                    */
/* ------------------------------------------------------------------------- */

static const char *const known_keys[] = {
    "PROJECT",            "REGION",            "ARCH",
    "SPOT_DEFAULT",       "AMI_POLICY",        "AMI_ID_AMD64",
    "AMI_ID_ARM64",       "AMI_SSM_AMD64",     "AMI_SSM_ARM64",
    "INSTANCE_TYPES_AMD64", "INSTANCE_TYPES_ARM64", "ROOT_VOLUME_SIZE",
    "ROOT_VOLUME_TYPE",   "KEY_NAME",          "SSH_IDENTITY",
    "SSH_USER",           "BUCKET_MODULES",    "ENABLE_IMAGE_BUILDER",
    "ENABLE_SPOT_ALERTS", "SPOT_ALERT_EMAIL",  "SETUP_ENTRYPOINT",
    "SERVICE_UNIT",       "SSH_PORT",          "OPERATOR_CIDR",
    "IP_ECHO_URL",        "INGRESS_TCP",       "INGRESS_UDP",
    "DDNS_HOST",          "DDNS_DOMAIN",       "DDNS_ONBOX",
    "RELEASE_TARGETS",    "BAZEL_COMMAND",     "ENABLE_CI_USER",
    "TEMPLATE_OVERRIDE",  "IMAGE_BUILDER_PARENT_IMAGE",
    "PERMISSIONS_BOUNDARY_ARN", NULL,
};

static int key_is_known(const char *key) {
    for (size_t i = 0; known_keys[i] != NULL; i++) {
        if (strcmp(known_keys[i], key) == 0) {
            return 1;
        }
    }
    return 0;
}

static const char *default_for(const char *key) {
    if (strcmp(key, "ROOT_VOLUME_TYPE") == 0) {
        return "gp3";
    }
    if (strcmp(key, "SSH_USER") == 0) {
        return "ec2-user";
    }
    if (strcmp(key, "ENABLE_SPOT_ALERTS") == 0) {
        return "false";
    }
    if (strcmp(key, "DDNS_ONBOX") == 0) {
        return "false";
    }
    if (strcmp(key, "IP_ECHO_URL") == 0) {
        return "https://checkip.amazonaws.com";
    }
    if (strcmp(key, "BAZEL_COMMAND") == 0) {
        return "bazel";
    }
    if (strcmp(key, "SETUP_ENTRYPOINT") == 0) {
        return "deploy.sh";
    }
    if (strcmp(key, "SSH_PORT") == 0) {
        return "22";
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Small validators                                                          */
/* ------------------------------------------------------------------------- */

static int project_is_valid(const char *value) {
    size_t len = strlen(value);

    if (len < 2 || !(value[0] >= 'a' && value[0] <= 'z')) {
        return 0;
    }
    for (size_t i = 1; i < len; i++) {
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9'))) {
            return 0;
        }
    }
    return 1;
}

static int region_is_valid(const char *value) {
    size_t len = strlen(value);

    if (len == 0 || len > 64 || !(value[0] >= 'a' && value[0] <= 'z')) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '-')) {
            return 0;
        }
    }
    return value[len - 1] != '-';
}

static int bool_is_valid(const char *value) {
    return strcmp(value, "true") == 0 || strcmp(value, "false") == 0;
}

/*
 * ARN shape: `arn:<partition>:<service>:<region>:<account>:<resource>`. Region
 * and account may be empty (global services); partition, service and resource
 * must be present. Whitespace is rejected.
 */
static int arn_shape_is_valid(const char *value) {
    const char *partition;
    const char *service;
    const char *last;
    size_t colons = 0;

    if (value == NULL || strncmp(value, "arn:", 4) != 0) {
        return 0;
    }
    for (const char *cursor = value; *cursor != '\0'; cursor++) {
        if (*cursor == ':') {
            colons++;
        } else if (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' ||
                   *cursor == '\r') {
            return 0;
        }
    }
    if (colons < 5) {
        return 0;
    }

    partition = value + 4;
    service = strchr(partition, ':');
    if (service == NULL || service == partition) {
        return 0;
    }
    service++;
    if (*service == ':' || *service == '\0') {
        return 0;
    }
    last = strrchr(value, ':');
    return last != NULL && last[1] != '\0';
}

/*
 * Image Builder accepts a parent image in exactly two shapes: a raw EC2 AMI
 * id, or a full SSM parameter ARN. A bare SSM parameter path is rejected
 * because the service cannot resolve it without an account-owned ARN.
 */
static int ami_id_is_valid(const char *value) {
    size_t len;

    if (value == NULL || strncmp(value, "ami-", 4) != 0) {
        return 0;
    }
    len = strlen(value + 4);
    if (len < 8 || len > 17) {
        return 0;
    }
    for (const char *hex = value + 4; *hex != '\0'; hex++) {
        if (!((*hex >= '0' && *hex <= '9') || (*hex >= 'a' && *hex <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int ssm_parameter_arn_is_valid(const char *value) {
    static const char prefix[] = "arn:aws:ssm:";
    const char *region;
    const char *account;
    const char *resource;
    size_t region_len;
    size_t account_len;

    if (value == NULL || strncmp(value, prefix, sizeof(prefix) - 1) != 0) {
        return 0;
    }
    region = value + sizeof(prefix) - 1;
    account = strchr(region, ':');
    if (account == NULL) {
        return 0;
    }
    region_len = (size_t)(account - region);
    if (region_len == 0) {
        return 0;
    }
    for (const char *c = region; c < account; c++) {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') ||
              *c == '-')) {
            return 0;
        }
    }

    account++;
    resource = strchr(account, ':');
    if (resource == NULL) {
        return 0;
    }
    account_len = (size_t)(resource - account);
    if (account_len != 12) {
        return 0;
    }
    for (const char *c = account; c < resource; c++) {
        if (*c < '0' || *c > '9') {
            return 0;
        }
    }

    resource++;
    return strncmp(resource, "parameter/", 10) == 0 && resource[10] != '\0';
}

static int builder_parent_image_is_valid(const char *value) {
    return ami_id_is_valid(value) || ssm_parameter_arn_is_valid(value);
}

static int parse_uint(const char *value, long min, long max, long *out) {
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < min ||
        parsed > max) {
        return 0;
    }
    *out = parsed;
    return 1;
}

/* Longest PROJECT length whose `<project>-artifacts-<acct>-<region>` bucket
 * still fits S3's 63-character limit. */
static size_t project_length_limit(const char *region) {
    size_t region_len = strlen(region);
    size_t used = BUCKET_FIXED_PREFIX_CHARS + region_len;

    if (used >= S3_BUCKET_NAME_MAX) {
        return 0;
    }
    return S3_BUCKET_NAME_MAX - used;
}

static int arch_is_amd64(const char *arch) {
    return strcmp(arch, "amd64") == 0 || strcmp(arch, "both") == 0;
}

static int arch_is_arm64(const char *arch) {
    return strcmp(arch, "arm64") == 0 || strcmp(arch, "both") == 0;
}

/* ------------------------------------------------------------------------- */
/* Comma-list validation                                                     */
/* ------------------------------------------------------------------------- */

typedef int (*field_check_fn)(const char *field, size_t len, void *ctx);

static void trim_field(const char **field, size_t *len) {
    while (*len > 0 && ((*field)[0] == ' ' || (*field)[0] == '\t')) {
        (*field)++;
        (*len)--;
    }
    while (*len > 0 &&
           ((*field)[*len - 1] == ' ' || (*field)[*len - 1] == '\t')) {
        (*len)--;
    }
}

static int csv_each(const char *value, field_check_fn check, void *ctx) {
    const char *start = value;

    for (;;) {
        const char *comma = strchr(start, ',');
        size_t len = comma != NULL ? (size_t)(comma - start) : strlen(start);

        if (!check(start, len, ctx)) {
            return 0;
        }
        if (comma == NULL) {
            return 1;
        }
        start = comma + 1;
    }
}

static int field_is_nonempty(const char *field, size_t len, void *ctx) {
    (void)ctx;
    trim_field(&field, &len);
    return len > 0;
}

typedef struct {
    int saw_artifact;
} bucket_modules_ctx;

static int bucket_module_field(const char *field, size_t len, void *ctx) {
    bucket_modules_ctx *modules = ctx;

    trim_field(&field, &len);
    if (len == 8 && strncmp(field, "artifact", len) == 0) {
        modules->saw_artifact = 1;
        return 1;
    }
    if (len == 4 && strncmp(field, "cert", len) == 0) {
        return 1;
    }
    return 0;
}

/* Each ingress entry is `port` or `port:cidr`. */
/*
 * Parse one strict IPv4 CIDR ("a.b.c.d/prefix") into canonical form. Rejects
 * IPv6 (any ':'), malformed octets/prefix, and host bits set below the prefix.
 * Returns 0 on success, or a negative marker via `reason_out`; the caller turns
 * that into a protocol-specific diagnostic.
 */
static int cidr_parse(const char *text, char *out, size_t cap,
                      const char **reason_out) {
    const char *slash = strchr(text, '/');
    unsigned octets[4] = {0};
    unsigned prefix = 0;
    unsigned addr = 0;
    unsigned mask;
    const char *cursor = text;
    char prefix_text[4];
    size_t prefix_len;

    *reason_out = NULL;
    if (strchr(text, ':') != NULL) {
        *reason_out = "IPv6 is not supported (IPv4 CIDR only)";
        return 0;
    }
    if (slash == NULL || strchr(slash + 1, '/') != NULL) {
        *reason_out = "CIDR must be IPv4/prefix (e.g. 0.0.0.0/0)";
        return 0;
    }

    for (int i = 0; i < 4; i++) {
        const char *end = i == 3 ? slash : strchr(cursor, '.');

        if (end == NULL || end == cursor) {
            *reason_out = "CIDR must have four dotted octets";
            return 0;
        }
        for (const char *p = cursor; p < end; p++) {
            if (p[0] < '0' || p[0] > '9') {
                *reason_out = "CIDR octets must be decimal 0..255";
                return 0;
            }
        }
        {
            char octet_text[4] = {0};
            size_t octet_len = (size_t)(end - cursor);

            if (octet_len >= sizeof octet_text) {
                *reason_out = "CIDR octet out of range (0..255)";
                return 0;
            }
            memcpy(octet_text, cursor, octet_len);
            octets[i] = (unsigned)strtoul(octet_text, NULL, 10);
            if (octets[i] > 255) {
                *reason_out = "CIDR octet out of range (0..255)";
                return 0;
            }
        }
        cursor = end + 1;
    }

    prefix_len = strlen(slash + 1);
    if (prefix_len == 0 || prefix_len >= sizeof prefix_text) {
        *reason_out = "CIDR prefix must be 0..32";
        return 0;
    }
    for (size_t i = 0; i < prefix_len; i++) {
        if (slash[1 + i] < '0' || slash[1 + i] > '9') {
            *reason_out = "CIDR prefix must be 0..32";
            return 0;
        }
    }
    memcpy(prefix_text, slash + 1, prefix_len);
    prefix_text[prefix_len] = '\0';
    prefix = (unsigned)strtoul(prefix_text, NULL, 10);
    if (prefix > 32) {
        *reason_out = "CIDR prefix must be 0..32";
        return 0;
    }

    addr = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    if ((addr & ~mask) != 0) {
        *reason_out = "CIDR has host bits set for its prefix";
        return 0;
    }

    snprintf(out, cap, "%u.%u.%u.%u/%u", octets[0], octets[1], octets[2],
             octets[3], prefix);
    return 1;
}

static int ingress_rule_exists(const config_ingress_rule *rules, size_t count,
                               unsigned port, const char *cidr) {
    for (size_t i = 0; i < count; i++) {
        if (rules[i].port == port && strcmp(rules[i].cidr, cidr) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Number of comma-separated items in a non-empty list (whitespace ignored). */
static size_t csv_item_count(const char *value) {
    size_t count = 1;

    for (const char *cursor = value; *cursor != '\0'; cursor++) {
        if (*cursor == ',') {
            count++;
        }
    }
    return count;
}

/*
 * Parse a full `port[:cidr]` comma list for one protocol into `rules`. An empty
 * value means no rules. Malformed entries, exact duplicates, IPv6, ranges, CIDR
 * violations and more than CONFIG_INGRESS_MAX rules are hard errors.
 */
static int ingress_list_parse(const char *value, const char *protocol,
                              config_ingress_rule *rules, size_t *count_out) {
    const char *start = value;

    *count_out = 0;
    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    for (;;) {
        const char *comma = strchr(start, ',');
        const char *field = start;
        size_t len = comma != NULL ? (size_t)(comma - start) : strlen(start);
        char item[128];
        char port_text[16];
        const char *colon;
        size_t port_len;
        long port_number;
        const char *cidr = "0.0.0.0/0";
        char cidr_text[19] = "0.0.0.0/0";
        const char *reason = NULL;

        trim_field(&field, &len);
        if (len == 0) {
            return cfg_error(EINVAL,
                             "%s has an empty entry (trailing comma?)",
                             protocol);
        }
        if (*count_out >= CONFIG_INGRESS_MAX) {
            return cfg_error(EINVAL,
                             "%s has %zu rules, exceeding the %d-slot limit "
                             "per protocol",
                             protocol, csv_item_count(value), CONFIG_INGRESS_MAX);
        }
        if (len >= sizeof item) {
            return cfg_error(EINVAL, "%s entry is too long", protocol);
        }
        memcpy(item, field, len);
        item[len] = '\0';

        colon = strchr(item, ':');
        port_len = colon != NULL ? (size_t)(colon - item) : strlen(item);
        if (port_len == 0 || port_len >= sizeof port_text) {
            return cfg_error(EINVAL, "%s entry has an invalid port", protocol);
        }
        memcpy(port_text, item, port_len);
        port_text[port_len] = '\0';
        if (!parse_uint(port_text, 1, 65535, &port_number)) {
            return cfg_error(EINVAL,
                             "%s entry has an invalid port (1..65535, no "
                             "ranges)",
                             protocol);
        }
        if (colon != NULL) {
            if (colon[1] == '\0') {
                return cfg_error(EINVAL, "%s entry has an empty CIDR",
                                 protocol);
            }
            if (!cidr_parse(colon + 1, cidr_text, sizeof cidr_text, &reason)) {
                return cfg_error(EINVAL, "%s entry \"%s\": %s", protocol, item,
                                 reason != NULL ? reason : "invalid CIDR");
            }
            cidr = cidr_text;
        }

        if (ingress_rule_exists(rules, *count_out, (unsigned)port_number, cidr)) {
            return cfg_error(EINVAL,
                             "%s has a duplicate rule %u:%s", protocol,
                             (unsigned)port_number, cidr);
        }
        rules[*count_out].port = (unsigned)port_number;
        snprintf(rules[*count_out].cidr, sizeof rules[*count_out].cidr, "%s",
                 cidr);
        (*count_out)++;

        if (comma == NULL) {
            return 0;
        }
        start = comma + 1;
    }
}

/* ------------------------------------------------------------------------- */
/* Required-key helpers                                                      */
/* ------------------------------------------------------------------------- */

static int require_key(const config_envfile *env, const char *key, int allow_empty) {
    const char *value = config_envfile_get(env, key);

    if (value == NULL) {
        return cfg_error(EINVAL, "missing required key %s", key);
    }
    if (!allow_empty && value[0] == '\0') {
        return cfg_error(EINVAL, "required key %s is empty", key);
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Validation                                                                */
/* ------------------------------------------------------------------------- */

struct validated {
    char *region;
    const char *project;
    const char *arch;
    const char *arch_list[3];
    config_ingress_rule ingress_tcp[CONFIG_INGRESS_MAX];
    size_t ingress_tcp_count;
    config_ingress_rule ingress_udp[CONFIG_INGRESS_MAX];
    size_t ingress_udp_count;
};

static int validate_region_consistency(const config_envfile *env, int region_explicit,
                                       const char *region_flag,
                                       const char *config_dir,
                                       struct validated *out) {
    const char *declared = config_envfile_get(env, "REGION");
    const char *effective;

    if (declared == NULL || !region_is_valid(declared)) {
        return cfg_error(EINVAL, "REGION \"%s\" is missing or invalid",
                         declared != NULL ? declared : "");
    }

    if (region_explicit) {
        if (region_flag == NULL || !region_is_valid(region_flag)) {
            return cfg_error(EINVAL, "--region \"%s\" is not a valid region name",
                             region_flag != NULL ? region_flag : "");
        }
        if (strcmp(declared, region_flag) != 0) {
            return cfg_error(
                EINVAL,
                ".env.%s must declare REGION=%s exactly (declares REGION=%s)",
                region_flag, region_flag, declared);
        }
        effective = region_flag;
    } else {
        size_t need = strlen(config_dir) + strlen(".env.") + strlen(declared) + 2;
        char *sibling = malloc(need);

        if (sibling == NULL) {
            return cfg_error(ENOMEM, "out of memory resolving region variant");
        }
        snprintf(sibling, need, "%s/.env.%s", config_dir, declared);
        if (access(sibling, F_OK) == 0) {
            free(sibling);
            return cfg_error(
                EINVAL,
                "plain .env declares REGION=%s but .env.%s exists; pass --region %s",
                declared, declared, declared);
        }
        free(sibling);
        effective = declared;
    }

    out->region = strdup(effective);
    if (out->region == NULL) {
        return cfg_error(ENOMEM, "out of memory copying region");
    }
    return 0;
}

static int validate_cross_keys(const config_envfile *env, const char *arch) {
    const char *policy = config_envfile_get(env, "AMI_POLICY");
    const char *spot_alerts = config_envfile_get(env, "ENABLE_SPOT_ALERTS");
    const char *ddns_onbox = config_envfile_get(env, "DDNS_ONBOX");
    const char *ddns_host = config_envfile_get(env, "DDNS_HOST");
    const char *ddns_domain = config_envfile_get(env, "DDNS_DOMAIN");
    const char *builder_parent =
        config_envfile_get(env, "IMAGE_BUILDER_PARENT_IMAGE");
    const char *boundary = config_envfile_get(env, "PERMISSIONS_BOUNDARY_ARN");
    int rc;

    /* AMI policy ↔ AMI_ID_* / AMI_SSM_*. */
    if (strcmp(policy, "pinned") == 0) {
        if (arch_is_amd64(arch) &&
            (rc = require_key(env, "AMI_ID_AMD64", 0)) != 0) {
            return rc;
        }
        if (arch_is_arm64(arch) &&
            (rc = require_key(env, "AMI_ID_ARM64", 0)) != 0) {
            return rc;
        }
    } else if (config_envfile_get(env, "AMI_ID_AMD64") != NULL ||
               config_envfile_get(env, "AMI_ID_ARM64") != NULL) {
        return cfg_error(
            EINVAL,
            "AMI_ID_* is only valid when AMI_POLICY=pinned (AMI_POLICY=%s)",
            policy);
    }

    if (strcmp(policy, "ssm") == 0) {
        if (arch_is_amd64(arch) &&
            (rc = require_key(env, "AMI_SSM_AMD64", 0)) != 0) {
            return rc;
        }
        if (arch_is_arm64(arch) &&
            (rc = require_key(env, "AMI_SSM_ARM64", 0)) != 0) {
            return rc;
        }
    }
    for (const char *const *key = (const char *const[]){
             "AMI_SSM_AMD64", "AMI_SSM_ARM64", NULL};
         *key != NULL; key++) {
        const char *value = config_envfile_get(env, *key);
        if (value != NULL && value[0] != '/') {
            return cfg_error(EINVAL,
                             "%s \"%s\" must be an absolute SSM parameter path "
                             "(starting with '/')",
                             *key, value);
        }
    }

    /* arm64 needs an arm64 instance-type allowlist. */
    if (arch_is_arm64(arch) &&
        (rc = require_key(env, "INSTANCE_TYPES_ARM64", 0)) != 0) {
        return rc;
    }

    /* Spot alerts need an email target; an email alone is harmless. */
    if (spot_alerts != NULL && strcmp(spot_alerts, "true") == 0) {
        if ((rc = require_key(env, "SPOT_ALERT_EMAIL", 0)) != 0) {
            return rc;
        }
    }

    /* DDNS: on-box install needs a host/domain pair; the pair travels together. */
    if (ddns_onbox != NULL && strcmp(ddns_onbox, "true") == 0) {
        if ((rc = require_key(env, "DDNS_HOST", 0)) != 0 ||
            (rc = require_key(env, "DDNS_DOMAIN", 0)) != 0) {
            return rc;
        }
    }
    if ((ddns_host != NULL) != (ddns_domain != NULL)) {
        return cfg_error(EINVAL,
                         "DDNS_HOST and DDNS_DOMAIN must be configured together");
    }

    /* F11: the builder needs a parent image in an Image Builder-accepted shape.
     * The template passes it through verbatim, so a bare SSM path would reach
     * the service as an invalid parent. */
    {
        const char *builder = config_envfile_get(env, "ENABLE_IMAGE_BUILDER");
        int builder_on = builder != NULL && strcmp(builder, "true") == 0;

        if (builder_parent != NULL && builder_parent[0] == '\0') {
            return cfg_error(EINVAL,
                             "IMAGE_BUILDER_PARENT_IMAGE must not be empty");
        }
        if (builder_on) {
            if (builder_parent == NULL) {
                return cfg_error(
                    EINVAL,
                    "IMAGE_BUILDER_PARENT_IMAGE is required when "
                    "ENABLE_IMAGE_BUILDER=true");
            }
            if (!builder_parent_image_is_valid(builder_parent)) {
                return cfg_error(
                    EINVAL,
                    "IMAGE_BUILDER_PARENT_IMAGE \"%s\" must be an EC2 AMI id "
                    "(ami-[0-9a-f]{8,17}) or a full SSM parameter ARN "
                    "(arn:aws:ssm:<region>:<account>:parameter/<path>)",
                    builder_parent);
            }
        } else if (builder_parent != NULL) {
            return cfg_error(EINVAL,
                             "IMAGE_BUILDER_PARENT_IMAGE is only valid when "
                             "ENABLE_IMAGE_BUILDER=true (ENABLE_IMAGE_BUILDER=%s)",
                             builder != NULL ? builder : "unset");
        }
    }

    /* F13: the optional permissions boundary must look like an ARN. */
    if (boundary != NULL) {
        if (boundary[0] == '\0') {
            return cfg_error(EINVAL,
                             "PERMISSIONS_BOUNDARY_ARN must not be empty");
        }
        if (!arn_shape_is_valid(boundary)) {
            return cfg_error(EINVAL,
                             "PERMISSIONS_BOUNDARY_ARN \"%s\" must be an ARN "
                             "(arn:<partition>:<service>:<region>:<account>:"
                             "<resource>)",
                             boundary);
        }
    }
    return 0;
}

static int validate_config(const config_envfile *env, int region_explicit,
                           const char *region_flag, const char *config_dir,
                           struct validated *out) {
    static const char *const required_nonempty[] = {
        "PROJECT",          "ARCH",        "SPOT_DEFAULT",
        "AMI_POLICY",       "INSTANCE_TYPES_AMD64", "ROOT_VOLUME_SIZE",
        "KEY_NAME",         "SSH_IDENTITY", "BUCKET_MODULES",
        "ENABLE_IMAGE_BUILDER", "RELEASE_TARGETS", "ENABLE_CI_USER", NULL,
    };
    static const char *const required_present[] = {
        "OPERATOR_CIDR", "INGRESS_TCP", "INGRESS_UDP", NULL,
    };
    const char *project;
    const char *arch;
    const char *policy;
    long number;
    size_t limit;
    int rc;

    /* v0.2.0: RELEASE_PREFIXES is removed. A present key fails fast with the
     * migration instruction rather than the generic unknown-key error. */
    for (size_t i = 0; i < config_envfile_count(env); i++) {
        if (strcmp(config_envfile_key_at(env, i), "RELEASE_PREFIXES") == 0) {
            return cfg_error(
                EINVAL,
                "RELEASE_PREFIXES was removed in v0.2.0; set "
                "ENABLE_CI_USER=true if it was non-empty, false if it was "
                "empty");
        }
    }

    /* Unknown keys are errors, never warnings. */
    for (size_t i = 0; i < config_envfile_count(env); i++) {
        const char *key = config_envfile_key_at(env, i);
        if (!key_is_known(key)) {
            return cfg_error(EINVAL, "unknown configuration key %s", key);
        }
    }

    for (const char *const *key = required_nonempty; *key != NULL; key++) {
        if ((rc = require_key(env, *key, 0)) != 0) {
            return rc;
        }
    }
    for (const char *const *key = required_present; *key != NULL; key++) {
        if ((rc = require_key(env, *key, 1)) != 0) {
            return rc;
        }
    }

    project = config_envfile_get(env, "PROJECT");
    arch = config_envfile_get(env, "ARCH");
    policy = config_envfile_get(env, "AMI_POLICY");

    /* PROJECT: ^[a-z][a-z0-9]+$ — no hyphens, uppercase, or leading digit. */
    if (!project_is_valid(project)) {
        return cfg_error(EINVAL,
                         "PROJECT \"%s\" must match ^[a-z][a-z0-9]+$ "
                         "(no hyphens, uppercase, or leading digit)",
                         project);
    }

    if ((rc = validate_region_consistency(env, region_explicit, region_flag,
                                          config_dir, out)) != 0) {
        return rc;
    }

    /* PROJECT length must keep the longest derived bucket within 63 chars. */
    limit = project_length_limit(out->region);
    if (strlen(project) > limit) {
        return cfg_error(
            EINVAL,
            "PROJECT \"%s\" length %zu exceeds limit %zu for REGION=%s: "
            "<project>-artifacts-<acct>-<region> must be <= %d characters",
            project, strlen(project), limit, out->region, S3_BUCKET_NAME_MAX);
    }

    if (strcmp(arch, "amd64") != 0 && strcmp(arch, "arm64") != 0 &&
        strcmp(arch, "both") != 0) {
        return cfg_error(EINVAL,
                         "ARCH \"%s\" must be amd64, arm64, or both", arch);
    }
    if (strcmp(policy, "pinned") != 0 && strcmp(policy, "ssm") != 0 &&
        strcmp(policy, "baked") != 0) {
        return cfg_error(
            EINVAL, "AMI_POLICY \"%s\" must be pinned, ssm, or baked", policy);
    }
    if (!bool_is_valid(config_envfile_get(env, "SPOT_DEFAULT"))) {
        return cfg_error(EINVAL, "SPOT_DEFAULT must be true or false");
    }
    if (!bool_is_valid(config_envfile_get(env, "ENABLE_IMAGE_BUILDER"))) {
        return cfg_error(EINVAL, "ENABLE_IMAGE_BUILDER must be true or false");
    }
    if (!bool_is_valid(config_envfile_get(env, "ENABLE_CI_USER"))) {
        return cfg_error(EINVAL, "ENABLE_CI_USER must be true or false");
    }
    if (config_envfile_get(env, "ENABLE_SPOT_ALERTS") != NULL &&
        !bool_is_valid(config_envfile_get(env, "ENABLE_SPOT_ALERTS"))) {
        return cfg_error(EINVAL, "ENABLE_SPOT_ALERTS must be true or false");
    }
    if (config_envfile_get(env, "DDNS_ONBOX") != NULL &&
        !bool_is_valid(config_envfile_get(env, "DDNS_ONBOX"))) {
        return cfg_error(EINVAL, "DDNS_ONBOX must be true or false");
    }

    if (!parse_uint(config_envfile_get(env, "ROOT_VOLUME_SIZE"), 1, 65536, &number)) {
        return cfg_error(EINVAL, "ROOT_VOLUME_SIZE must be an integer in 1..65536");
    }
    if (config_envfile_get(env, "SSH_PORT") != NULL &&
        !parse_uint(config_envfile_get(env, "SSH_PORT"), 1, 65535, &number)) {
        return cfg_error(EINVAL, "SSH_PORT must be an integer in 1..65535");
    }
    if (config_envfile_get(env, "ROOT_VOLUME_TYPE") != NULL &&
        config_envfile_get(env, "ROOT_VOLUME_TYPE")[0] == '\0') {
        return cfg_error(EINVAL, "ROOT_VOLUME_TYPE must not be empty");
    }
    if (config_envfile_get(env, "SSH_USER") != NULL &&
        config_envfile_get(env, "SSH_USER")[0] == '\0') {
        return cfg_error(EINVAL, "SSH_USER must not be empty");
    }
    if (config_envfile_get(env, "SETUP_ENTRYPOINT") != NULL &&
        config_envfile_get(env, "SETUP_ENTRYPOINT")[0] == '\0') {
        return cfg_error(EINVAL, "SETUP_ENTRYPOINT must not be empty");
    }
    if (config_envfile_get(env, "SERVICE_UNIT") != NULL &&
        config_envfile_get(env, "SERVICE_UNIT")[0] == '\0') {
        return cfg_error(EINVAL, "SERVICE_UNIT must not be empty");
    }
    if (config_envfile_get(env, "TEMPLATE_OVERRIDE") != NULL &&
        config_envfile_get(env, "TEMPLATE_OVERRIDE")[0] == '\0') {
        return cfg_error(EINVAL, "TEMPLATE_OVERRIDE must not be empty");
    }

    /* Comma lists. */
    if (!csv_each(config_envfile_get(env, "INSTANCE_TYPES_AMD64"),
                  field_is_nonempty, NULL)) {
        return cfg_error(EINVAL,
                         "INSTANCE_TYPES_AMD64 must be a non-empty comma list");
    }
    if (config_envfile_get(env, "INSTANCE_TYPES_ARM64") != NULL &&
        !csv_each(config_envfile_get(env, "INSTANCE_TYPES_ARM64"), field_is_nonempty,
                  NULL)) {
        return cfg_error(EINVAL,
                         "INSTANCE_TYPES_ARM64 must be a non-empty comma list");
    }
    {
        bucket_modules_ctx modules = {0};
        if (!csv_each(config_envfile_get(env, "BUCKET_MODULES"),
                      bucket_module_field, &modules)) {
            return cfg_error(
                EINVAL, "BUCKET_MODULES entries must be 'artifact' or 'cert'");
        }
        if (!modules.saw_artifact) {
            return cfg_error(EINVAL,
                             "BUCKET_MODULES must include the 'artifact' module");
        }
    }
    {
        int ingress_rc;

        /* Empty lists mean "no rule"; everything else is parsed fail-closed. */
        ingress_rc = ingress_list_parse(
            config_envfile_get(env, "INGRESS_TCP"), "INGRESS_TCP",
            out->ingress_tcp, &out->ingress_tcp_count);
        if (ingress_rc != 0) {
            return ingress_rc;
        }
        ingress_rc = ingress_list_parse(
            config_envfile_get(env, "INGRESS_UDP"), "INGRESS_UDP",
            out->ingress_udp, &out->ingress_udp_count);
        if (ingress_rc != 0) {
            return ingress_rc;
        }
    }
    if (!csv_each(config_envfile_get(env, "RELEASE_TARGETS"), field_is_nonempty,
                  NULL)) {
        return cfg_error(EINVAL,
                         "RELEASE_TARGETS must be a non-empty comma list");
    }
    if ((rc = validate_cross_keys(env, arch)) != 0) {
        return rc;
    }

    out->project = project;
    out->arch = arch;
    if (strcmp(arch, "both") == 0) {
        out->arch_list[0] = "amd64";
        out->arch_list[1] = "arm64";
        out->arch_list[2] = NULL;
    } else {
        out->arch_list[0] = arch;
        out->arch_list[1] = NULL;
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Path helpers                                                              */
/* ------------------------------------------------------------------------- */

static char *path_join(const char *dir, const char *name) {
    size_t need = strlen(dir) + strlen(name) + 2;
    char *path = malloc(need);

    if (path == NULL) {
        return NULL;
    }
    snprintf(path, need, "%s/%s", dir, name);
    return path;
}

static int path_is_within(const char *path, const char *root) {
    size_t root_len = strlen(root);

    if (root_len == 0) {
        return 0;
    }
    if (root_len == 1 && root[0] == '/') {
        return path[0] == '/';
    }
    if (strncmp(path, root, root_len) != 0) {
        return 0;
    }
    return path[root_len] == '\0' || path[root_len] == '/';
}

/* Resolve `dir` against $BUILD_WORKING_DIRECTORY when set, else cwd. */
static char *resolve_config_dir(const char *dir) {
    const char *base;
    char cwd[PATH_MAX];

    if (dir[0] == '/') {
        return strdup(dir);
    }
    base = config_build_working_directory();
    if (base == NULL) {
        if (getcwd(cwd, sizeof cwd) == NULL) {
            return NULL;
        }
        base = cwd;
    }
    return path_join(base, dir);
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

const char *config_build_working_directory(void) {
    const char *value = getenv("BUILD_WORKING_DIRECTORY");

    return value != NULL && value[0] != '\0' ? value : NULL;
}

int config_repo_root(const char *config_dir, char **root_out) {
    char *current;

    if (config_dir == NULL || root_out == NULL) {
        return EINVAL;
    }
    *root_out = NULL;

    current = realpath(config_dir, NULL);
    if (current == NULL) {
        return errno != 0 ? errno : ENOENT;
    }

    for (;;) {
        char *marker = path_join(current, "MODULE.bazel");
        struct stat status;

        if (marker == NULL) {
            free(current);
            return ENOMEM;
        }
        if (stat(marker, &status) == 0 && S_ISREG(status.st_mode)) {
            free(marker);
            *root_out = current;
            return 0;
        }
        free(marker);

        if (strcmp(current, "/") == 0) {
            break;
        }
        {
            char *slash = strrchr(current, '/');

            if (slash == NULL) {
                break;
            }
            if (slash == current) {
                current[1] = '\0'; /* keep "/" */
            } else {
                *slash = '\0';
            }
        }
    }

    free(current);
    return ENOENT;
}

int config_load(const char *dir, int region_explicit, const char *region_flag,
                stackctl_config **out) {
    char *resolved_dir = NULL;
    char *real_dir = NULL;
    char *file_path = NULL;
    char *file_real = NULL;
    char *root = NULL;
    config_envfile *env = NULL;
    struct validated validated;
    stackctl_config *cfg = NULL;
    int rc = EINVAL;

    memset(&validated, 0, sizeof validated);

    if (out == NULL) {
        return EINVAL;
    }
    *out = NULL;
    if (dir == NULL || dir[0] == '\0') {
        return cfg_error(EINVAL, "--project config directory is empty");
    }

    resolved_dir = resolve_config_dir(dir);
    if (resolved_dir == NULL) {
        return cfg_error(errno != 0 ? errno : ENOMEM,
                         "could not resolve config directory \"%s\"", dir);
    }
    real_dir = realpath(resolved_dir, NULL);
    free(resolved_dir);
    if (real_dir == NULL) {
        rc = errno != 0 ? errno : ENOENT;
        return cfg_error(rc, "could not resolve config directory \"%s\": %s",
                         dir, strerror(rc));
    }

    if (region_explicit) {
        if (region_flag == NULL || !region_is_valid(region_flag)) {
            rc = cfg_error(EINVAL,
                           "--region \"%s\" is not a valid region name",
                           region_flag != NULL ? region_flag : "");
            goto cleanup;
        }
        {
            size_t need = strlen(".env.") + strlen(region_flag) + 1;
            char *name = malloc(need);

            if (name == NULL) {
                rc = cfg_error(ENOMEM, "out of memory resolving region variant");
                goto cleanup;
            }
            snprintf(name, need, ".env.%s", region_flag);
            file_path = path_join(real_dir, name);
            free(name);
        }
        if (file_path == NULL) {
            rc = cfg_error(ENOMEM, "out of memory resolving region variant");
            goto cleanup;
        }
        if (access(file_path, R_OK) != 0) {
            rc = cfg_error(ENOENT, "region config %s does not exist",
                           file_path);
            goto cleanup;
        }
    } else {
        file_path = path_join(real_dir, ".env");
        if (file_path == NULL) {
            rc = cfg_error(ENOMEM, "out of memory resolving .env");
            goto cleanup;
        }
        if (access(file_path, R_OK) != 0) {
            rc = cfg_error(ENOENT, "config file %s does not exist", file_path);
            goto cleanup;
        }
    }

    {
        char errbuf[512];

        if (config_envfile_load(file_path, &env, errbuf, sizeof errbuf) != 0) {
            rc = cfg_error(EINVAL, "%s", errbuf);
            goto cleanup;
        }
    }

    rc = config_repo_root(real_dir, &root);
    if (rc != 0) {
        rc = cfg_error(rc, "no repo root containing MODULE.bazel found above %s",
                       real_dir);
        goto cleanup;
    }

    file_real = realpath(file_path, NULL);
    if (file_real == NULL) {
        rc = errno != 0 ? errno : ENOENT;
        rc = cfg_error(rc, "could not resolve config file %s: %s", file_path,
                       strerror(rc));
        goto cleanup;
    }
    if (!path_is_within(file_real, root)) {
        rc = cfg_error(EINVAL,
                       "config file %s resolves outside repo root %s",
                       file_real, root);
        goto cleanup;
    }

    rc = validate_config(env, region_explicit, region_flag, real_dir,
                         &validated);
    if (rc != 0) {
        goto cleanup;
    }

    cfg = calloc(1, sizeof *cfg);
    if (cfg == NULL) {
        rc = cfg_error(ENOMEM, "out of memory allocating config");
        goto cleanup;
    }
    cfg->env = env;
    env = NULL;
    cfg->dir = real_dir;
    real_dir = NULL;
    cfg->file = file_real;
    file_real = NULL;
    cfg->repo_root = root;
    root = NULL;
    cfg->region = validated.region;
    validated.region = NULL;
    cfg->project = validated.project;
    cfg->arch = validated.arch;
    memcpy(cfg->arch_list, validated.arch_list, sizeof cfg->arch_list);
    cfg->image_builder_parent_image =
        config_envfile_get(cfg->env, "IMAGE_BUILDER_PARENT_IMAGE");
    cfg->permissions_boundary_arn =
        config_envfile_get(cfg->env, "PERMISSIONS_BOUNDARY_ARN");
    memcpy(cfg->ingress_tcp, validated.ingress_tcp,
           sizeof cfg->ingress_tcp);
    cfg->ingress_tcp_count = validated.ingress_tcp_count;
    memcpy(cfg->ingress_udp, validated.ingress_udp,
           sizeof cfg->ingress_udp);
    cfg->ingress_udp_count = validated.ingress_udp_count;

    *out = cfg;
    cfg = NULL;
    rc = 0;

cleanup:
    free(file_path);
    free(file_real);
    free(root);
    free(real_dir);
    free(validated.region);
    config_envfile_free(env);
    config_free(cfg);
    return rc;
}

void config_free(stackctl_config *cfg) {
    if (cfg == NULL) {
        return;
    }
    config_envfile_free(cfg->env);
    free(cfg->dir);
    free(cfg->file);
    free(cfg->repo_root);
    free(cfg->region);
    free(cfg);
}

const char *config_get(const stackctl_config *cfg, const char *key) {
    const char *value;

    if (cfg == NULL || key == NULL) {
        return NULL;
    }
    if (strcmp(key, "REGION") == 0) {
        return cfg->region;
    }
    if (strcmp(key, "PROJECT") == 0) {
        return cfg->project;
    }
    if (strcmp(key, "ARCH") == 0) {
        return cfg->arch;
    }
    value = config_envfile_get(cfg->env, key);
    if (value != NULL) {
        return value;
    }
    return default_for(key);
}

const char *config_region(const stackctl_config *cfg) {
    return cfg == NULL ? NULL : cfg->region;
}

const char *config_project(const stackctl_config *cfg) {
    return cfg == NULL ? NULL : cfg->project;
}

const char *config_dir(const stackctl_config *cfg) {
    return cfg == NULL ? NULL : cfg->dir;
}

const char *const *config_arch_list(const stackctl_config *cfg) {
    return cfg == NULL ? NULL : cfg->arch_list;
}

const char *config_image_builder_parent_image(const stackctl_config *cfg) {
    return cfg == NULL ? NULL : cfg->image_builder_parent_image;
}

const char *config_permissions_boundary_arn(const stackctl_config *cfg) {
    return cfg == NULL ? NULL : cfg->permissions_boundary_arn;
}

size_t config_ingress_tcp(const stackctl_config *cfg,
                          const config_ingress_rule **rules_out) {
    if (rules_out != NULL) {
        *rules_out = cfg != NULL && cfg->ingress_tcp_count > 0
                         ? cfg->ingress_tcp
                         : NULL;
    }
    return cfg == NULL ? 0 : cfg->ingress_tcp_count;
}

size_t config_ingress_udp(const stackctl_config *cfg,
                          const config_ingress_rule **rules_out) {
    if (rules_out != NULL) {
        *rules_out = cfg != NULL && cfg->ingress_udp_count > 0
                         ? cfg->ingress_udp
                         : NULL;
    }
    return cfg == NULL ? 0 : cfg->ingress_udp_count;
}
