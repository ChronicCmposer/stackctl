/*
 * instance_dns.c — DDNS orchestration shared by launch and terminate:
 * authoritative-NS snapshots, updates, bounded verification and the SSM
 * DDNS-password read. The password is never logged and never placed in argv.
 */

#include "instance.h"

#include <errno.h>
#include <string.h>
#include <time.h>

bool instance_ddns_configured(const instance_runtime *rt) {
    return rt != NULL && rt->cfg.ddns_host[0] != '\0' &&
           rt->cfg.ddns_domain[0] != '\0';
}

int instance_dns_snapshot(instance_runtime *rt, char *ip, size_t cap,
                          bool *parked) {
    char value[64] = {0};
    bool is_parked = false;
    int rc;

    if (rt == NULL || ip == NULL || !instance_ddns_configured(rt)) {
        return EINVAL;
    }
    if (rt->svc.dns_a_record == NULL) {
        return ENOSYS;
    }
    rc = rt->svc.dns_a_record(rt->cfg.ddns_domain, rt->cfg.ddns_host, value,
                              &is_parked);
    if (rc != 0) {
        return rc;
    }
    if (strlen(value) + 1 > cap) {
        return ENAMETOOLONG;
    }
    memcpy(ip, value, strlen(value) + 1);
    if (parked != NULL) {
        *parked = is_parked;
    }
    return 0;
}

int instance_ddns_set(instance_runtime *rt, const char *password,
                      const char *ip, bool *updated) {
    bool ok = false;
    int rc;

    if (rt == NULL || ip == NULL || !instance_ddns_configured(rt)) {
        return EINVAL;
    }
    if (rt->svc.ddns_update == NULL) {
        return ENOSYS;
    }
    rc = rt->svc.ddns_update(rt->cfg.ddns_host, rt->cfg.ddns_domain, password,
                             ip, &ok);
    if (updated != NULL) {
        *updated = ok;
    }
    return rc;
}

int instance_dns_verify(instance_runtime *rt, const char *expected_ip,
                        int attempts, int interval_sec) {
    if (rt == NULL || expected_ip == NULL || attempts < 1) {
        return EINVAL;
    }
    if (rt->svc.dns_a_record == NULL) {
        return ENOSYS;
    }
    for (int attempt = 0; attempt < attempts; attempt++) {
        char current[64] = {0};
        bool parked = false;
        int rc = rt->svc.dns_a_record(rt->cfg.ddns_domain, rt->cfg.ddns_host,
                                      current, &parked);

        if (rc == 0 && strcmp(current, expected_ip) == 0) {
            return 0;
        }
        if (attempt + 1 < attempts && interval_sec > 0) {
            struct timespec delay = {.tv_sec = interval_sec, .tv_nsec = 0};

            nanosleep(&delay, NULL);
        }
    }
    return ETIMEDOUT;
}

int instance_ddns_password(instance_runtime *rt, char *out, size_t cap) {
    char name[INST_SSM_PARAM_MAX];
    ssm_parameter parameter;
    int written;
    int rc;

    if (rt == NULL || out == NULL || rt->cfg.project[0] == '\0') {
        return EINVAL;
    }
    if (rt->svc.ssm_get_parameter == NULL) {
        return ENOSYS;
    }
    written = snprintf(name, sizeof name, "/%s/ddns/password", rt->cfg.project);
    if (written < 0 || (size_t)written >= sizeof name) {
        return ENAMETOOLONG;
    }
    memset(&parameter, 0, sizeof parameter);
    rc = rt->svc.ssm_get_parameter(rt->svc.ssm, name, 1, &parameter);
    if (rc != 0) {
        return rc;
    }
    if (parameter.value == NULL || parameter.value[0] == '\0') {
        ssm_parameter_free(&parameter);
        return ENOENT;
    }
    if (strlen(parameter.value) + 1 > cap) {
        ssm_parameter_free(&parameter);
        return ENAMETOOLONG;
    }
    memcpy(out, parameter.value, strlen(parameter.value) + 1);
    ssm_parameter_free(&parameter);
    return 0;
}
