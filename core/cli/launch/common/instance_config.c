/*
 * instance_config.c — snapshot the instance-verb-relevant configuration keys
 * out of the opaque, fully validated stackctl_config.
 */

#include "instance.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void copy_field(char *dst, size_t cap, const char *src) {
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    if (strlen(src) + 1 > cap) {
        dst[cap - 1] = '\0';
        return;
    }
    memcpy(dst, src, strlen(src) + 1);
}

static int parse_bool(const char *value) {
    if (value == NULL) {
        return 0;
    }
    return strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
           strcmp(value, "yes") == 0;
}

int instance_config_from_ctx(const cli_ctx *ctx, instance_config *out) {
    const stackctl_config *cfg;

    if (ctx == NULL || out == NULL) {
        return EINVAL;
    }
    cfg = cli_ctx_config(ctx);
    if (cfg == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof *out);
    copy_field(out->project, sizeof out->project, config_project(cfg));
    copy_field(out->region, sizeof out->region, config_region(cfg));
    copy_field(out->arch, sizeof out->arch, config_get(cfg, "ARCH"));
    out->spot_default = parse_bool(config_get(cfg, "SPOT_DEFAULT"));
    copy_field(out->ami_policy, sizeof out->ami_policy,
               config_get(cfg, "AMI_POLICY"));
    copy_field(out->ami_id_amd64, sizeof out->ami_id_amd64,
               config_get(cfg, "AMI_ID_AMD64"));
    copy_field(out->ami_id_arm64, sizeof out->ami_id_arm64,
               config_get(cfg, "AMI_ID_ARM64"));
    copy_field(out->ami_ssm_amd64, sizeof out->ami_ssm_amd64,
               config_get(cfg, "AMI_SSM_AMD64"));
    copy_field(out->ami_ssm_arm64, sizeof out->ami_ssm_arm64,
               config_get(cfg, "AMI_SSM_ARM64"));
    copy_field(out->instance_types_amd64, sizeof out->instance_types_amd64,
               config_get(cfg, "INSTANCE_TYPES_AMD64"));
    copy_field(out->instance_types_arm64, sizeof out->instance_types_arm64,
               config_get(cfg, "INSTANCE_TYPES_ARM64"));
    out->root_volume_size_gb = 0;
    {
        const char *size = config_get(cfg, "ROOT_VOLUME_SIZE");

        if (size != NULL && size[0] != '\0') {
            out->root_volume_size_gb = (int)strtol(size, NULL, 10);
        }
    }
    copy_field(out->root_volume_type, sizeof out->root_volume_type,
               config_get(cfg, "ROOT_VOLUME_TYPE"));
    copy_field(out->key_name, sizeof out->key_name, config_get(cfg, "KEY_NAME"));
    copy_field(out->ssh_identity, sizeof out->ssh_identity,
               config_get(cfg, "SSH_IDENTITY"));
    copy_field(out->ssh_user, sizeof out->ssh_user, config_get(cfg, "SSH_USER"));
    out->ssh_port = 22;
    {
        const char *port = config_get(cfg, "SSH_PORT");

        if (port != NULL && port[0] != '\0') {
            out->ssh_port = (int)strtol(port, NULL, 10);
        }
    }
    copy_field(out->operator_cidr, sizeof out->operator_cidr,
               config_get(cfg, "OPERATOR_CIDR"));
    copy_field(out->service_unit, sizeof out->service_unit,
               config_get(cfg, "SERVICE_UNIT"));
    copy_field(out->setup_entrypoint, sizeof out->setup_entrypoint,
               config_get(cfg, "SETUP_ENTRYPOINT"));
    copy_field(out->ddns_host, sizeof out->ddns_host, config_get(cfg, "DDNS_HOST"));
    copy_field(out->ddns_domain, sizeof out->ddns_domain,
               config_get(cfg, "DDNS_DOMAIN"));
    out->ddns_onbox = parse_bool(config_get(cfg, "DDNS_ONBOX"));
    copy_field(out->bucket_modules, sizeof out->bucket_modules,
               config_get(cfg, "BUCKET_MODULES"));
    copy_field(out->ip_echo_url, sizeof out->ip_echo_url,
               config_get(cfg, "IP_ECHO_URL"));
    return 0;
}

bool instance_config_has(const instance_config *cfg, const char *key) {
    const char *value = NULL;

    if (cfg == NULL || key == NULL) {
        return false;
    }
    if (strcmp(key, "project") == 0) {
        value = cfg->project;
    } else if (strcmp(key, "region") == 0) {
        value = cfg->region;
    } else if (strcmp(key, "key_name") == 0) {
        value = cfg->key_name;
    } else if (strcmp(key, "ssh_identity") == 0) {
        value = cfg->ssh_identity;
    } else if (strcmp(key, "operator_cidr") == 0) {
        value = cfg->operator_cidr;
    } else if (strcmp(key, "service_unit") == 0) {
        value = cfg->service_unit;
    } else if (strcmp(key, "ddns_host") == 0) {
        value = cfg->ddns_host;
    } else if (strcmp(key, "ddns_domain") == 0) {
        value = cfg->ddns_domain;
    }
    return value != NULL && value[0] != '\0';
}
