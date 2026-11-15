/*
 * instance_runtime.c — runtime plumbing: streams, confirmation, diagnostics
 * and audit logging shared by the instance verbs.
 */

#include "instance.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static int ctx_confirm(void *ud, const char *prompt) {
    return cli_confirm((cli_ctx *)ud, prompt);
}

/* Default launch-record sink: a NULL store is a no-op (unit tests). */
static int default_launch_record_append(state_store *store,
                                        const state_launch_record *record) {
    if (store == NULL) {
        return 0;
    }
    return state_launch_record_append(store, record);
}

void instance_runtime_init(instance_runtime *rt, const instance_config *cfg,
                           state_store *state, const instance_services *svc,
                           int json, int yes, int dry_run) {
    if (rt == NULL) {
        return;
    }
    memset(rt, 0, sizeof *rt);
    if (cfg != NULL) {
        rt->cfg = *cfg;
    }
    rt->state = state;
    if (svc != NULL) {
        rt->svc = *svc;
    }
    rt->json = json;
    rt->yes = yes;
    rt->dry_run = dry_run;
    rt->dns_attempts = 24;
    rt->dns_interval = 5;
    rt->wait_attempts = 60;
    rt->wait_interval = 5;
    rt->ssh_attempts = 60;
    rt->ssh_interval = 5;
    rt->launch_record_append = default_launch_record_append;
    rt->out = stdout;
    rt->err = stderr;
}

int instance_runtime_from_ctx(instance_runtime *rt, cli_ctx *ctx,
                              const instance_services *svc) {
    if (rt == NULL || ctx == NULL) {
        return EINVAL;
    }
    memset(rt, 0, sizeof *rt);
    if (instance_config_from_ctx(ctx, &rt->cfg) != 0) {
        return EINVAL;
    }
    rt->state = cli_ctx_state(ctx);
    if (svc != NULL) {
        rt->svc = *svc;
    }
    rt->json = cli_ctx_json(ctx);
    rt->yes = cli_ctx_yes(ctx);
    rt->dry_run = cli_ctx_dry_run(ctx);
    rt->dns_attempts = 24;
    rt->dns_interval = 5;
    rt->wait_attempts = 60;
    rt->wait_interval = 5;
    rt->ssh_attempts = 60;
    rt->ssh_interval = 5;
    rt->launch_record_append = default_launch_record_append;
    rt->out = stdout;
    rt->err = stderr;
    rt->confirm = ctx_confirm;
    rt->confirm_ud = ctx;
    return 0;
}

int instance_confirm(instance_runtime *rt, const char *prompt) {
    if (rt == NULL) {
        return CLI_CONFIRM_NONINTERACTIVE;
    }
    if (rt->yes != 0) {
        return CLI_CONFIRM_YES;
    }
    if (rt->confirm != NULL) {
        return rt->confirm(rt->confirm_ud, prompt);
    }
    return CLI_CONFIRM_NONINTERACTIVE;
}

void instance_out(instance_runtime *rt, const char *fmt, ...) {
    va_list args;
    FILE *out = rt != NULL && rt->out != NULL ? rt->out : stdout;

    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);
}

void instance_err(instance_runtime *rt, const char *fmt, ...) {
    va_list args;
    FILE *err = rt != NULL && rt->err != NULL ? rt->err : stderr;

    va_start(args, fmt);
    vfprintf(err, fmt, args);
    va_end(args);
}

void instance_warn(instance_runtime *rt, const char *fmt, ...) {
    va_list args;
    FILE *err = rt != NULL && rt->err != NULL ? rt->err : stderr;

    fputs("stackctl: warning: ", err);
    va_start(args, fmt);
    vfprintf(err, fmt, args);
    va_end(args);
    fputc('\n', err);
}

int instance_fail(instance_runtime *rt, int code, const char *fmt, ...) {
    va_list args;
    FILE *err = rt != NULL && rt->err != NULL ? rt->err : stderr;

    fputs("stackctl: ", err);
    va_start(args, fmt);
    vfprintf(err, fmt, args);
    va_end(args);
    fputc('\n', err);
    return code;
}

void instance_audit(instance_runtime *rt, const char *verb, const char *args,
                    const char *outcome) {
    if (rt == NULL || rt->state == NULL || verb == NULL) {
        return;
    }
    if (state_operations_log_append(rt->state, verb,
                                    args != NULL ? args : "", outcome) != 0) {
        instance_warn(rt, "could not append to the operations log");
    }
}
