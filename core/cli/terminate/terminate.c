/*
 * terminate.c — `stackctl terminate` (spec §4).
 *
 * Sweeps every Project-tagged instance in a live state (or exactly one
 * --instance-id that must carry the Project tag), waits for `terminated`,
 * parks the DDNS A record at 0.0.0.0 (unconditionally for the sweep, including
 * zero matches), verifies the park against the authoritative NS and forgets the
 * known-hosts bindings. The instance terminates server-side regardless of the
 * waiter, so a waiter error/timeout still parks DNS and forgets host keys
 * (best-effort) before exiting 5: leaving the record pointed at a dying
 * instance and the host-key store stale is worse than a late cleanup. A park
 * failure on the normal path is exit 5.
 */

#include "terminate_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const cli_option_spec terminate_option_specs[] = {
    {"instance-id", 0, 1, 0, "<id>",
     "terminate exactly one Project-tagged instance"},
};

const size_t terminate_option_count =
    sizeof terminate_option_specs / sizeof terminate_option_specs[0];

int terminate_wait_attempts(int interval_sec) {
    int attempts;

    if (interval_sec <= 0) {
        /* Test seam: no real sleep, but keep the budget in one-second slots. */
        return TERMINATE_WAIT_BUDGET_SEC;
    }
    attempts = TERMINATE_WAIT_BUDGET_SEC / interval_sec;
    return attempts > 0 ? attempts : 1;
}

/* Sleep between bounded polls; a zero/negative interval keeps tests instant. */
static void sleep_seconds(int seconds) {
    struct timespec delay;

    if (seconds <= 0) {
        return;
    }
    delay.tv_sec = seconds;
    delay.tv_nsec = 0;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

/*
 * Poll the termination waiter one attempt at a time so each poll can be
 * announced on stderr. A single-attempt call is exactly one aws_wait poll, so
 * the effective budget (polls x interval) and abort-check semantics are
 * unchanged. Returns 0 with *timed_out set, or a propagated waiter error.
 */
static int wait_terminated_with_progress(instance_runtime *rt,
                                         const char *const *ids, size_t count,
                                         int *timed_out) {
    int interval = rt->wait_interval > 0 ? rt->wait_interval : 0;
    int attempts = terminate_wait_attempts(interval);
    int elapsed = 0;

    *timed_out = 0;
    instance_err(rt,
                 "stackctl: waiting for termination of %zu instance(s) "
                 "(budget %ds)\n",
                 count, TERMINATE_WAIT_BUDGET_SEC);
    for (int attempt = 0; attempt < attempts; attempt++) {
        int step_timed_out = 0;
        int rc = rt->svc.ec2_wait_terminated(rt->svc.ec2, ids, count, 1, 0,
                                             &step_timed_out);

        if (rc != 0) {
            return rc;
        }
        if (!step_timed_out) {
            return 0;
        }
        elapsed += interval > 0 ? interval : 1;
        if (attempt + 1 < attempts) {
            if (elapsed % 15 == 0) {
                instance_err(rt,
                             "stackctl: waiting for termination (%ds elapsed / "
                             "budget %ds)\n",
                             elapsed, TERMINATE_WAIT_BUDGET_SEC);
            }
            sleep_seconds(interval);
        }
    }
    *timed_out = 1;
    return 0;
}

/* Read the DDNS password and park the record at 0.0.0.0, then verify it. */
static int park_record(instance_runtime *rt) {
    char password[INST_PATH_MAX];
    bool updated = false;
    int rc;

    if (!instance_ddns_configured(rt)) {
        return CLI_EXIT_OK;
    }
    rc = instance_ddns_password(rt, password, sizeof password);
    if (rc != 0) {
        return instance_fail(rt, CLI_EXIT_CLEANUP,
                             "cannot read the DDNS password to park the record");
    }
    rc = instance_ddns_set(rt, password, "0.0.0.0", &updated);
    memset(password, 0, sizeof password);
    if (rc != 0 || !updated) {
        return instance_fail(rt, CLI_EXIT_CLEANUP,
                             "failed to park the DDNS record at 0.0.0.0");
    }
    if (instance_dns_verify(rt, "0.0.0.0", rt->dns_attempts,
                            rt->dns_interval) != 0) {
        return instance_fail(rt, CLI_EXIT_CLEANUP,
                             "DDNS record did not verify as parked at 0.0.0.0");
    }
    return CLI_EXIT_OK;
}

static void forget_bindings(instance_runtime *rt, const char *const *ids,
                            size_t count) {
    const char *store = rt->state != NULL ? state_known_hosts_path(rt->state) : "";

    for (size_t i = 0; i < count; i++) {
        if (rt->svc.kh_forget != NULL) {
            (void)rt->svc.kh_forget(store, ids[i]);
        }
        if (rt->state != NULL) {
            (void)state_binding_forget(rt->state, ids[i]);
        }
    }
}

static void emit_result(instance_runtime *rt, const char *const *ids,
                        size_t count, bool parked) {
    if (rt->json) {
        instance_out(rt, "{\"verb\":\"terminate\",\"terminated\":[");
        for (size_t i = 0; i < count; i++) {
            instance_out(rt, "%s\"%s\"", i == 0 ? "" : ",", ids[i]);
        }
        instance_out(rt, "],\"parked\":%s}\n", parked ? "true" : "false");
        return;
    }
    if (count == 0) {
        instance_out(rt, "no matching instances\n");
    } else {
        instance_out(rt, "terminated:");
        for (size_t i = 0; i < count; i++) {
            instance_out(rt, " %s", ids[i]);
        }
        instance_out(rt, "\n");
    }
    if (parked) {
        instance_out(rt, "DDNS record parked at 0.0.0.0\n");
    }
}

int terminate_execute(instance_runtime *rt, const terminate_options *opts) {
    ec2_instance_list list;
    char id_storage[64][EC2_INSTANCE_ID_MAX];
    const char *ids[64];
    size_t id_count = 0;
    char target_ip[EC2_IP_MAX] = {0};
    char record_ip[64] = {0};
    bool parked = false;
    int waiter_failed = 0;
    int rc;
    int exit_code;

    if (rt == NULL || opts == NULL) {
        return CLI_EXIT_USAGE;
    }
    if (rt->cfg.project[0] == '\0') {
        return instance_fail(rt, CLI_EXIT_USAGE, "missing project");
    }
    /* Identity guard: re-assert the project identity before TerminateInstances. */
    rc = instance_identity_guard(rt);
    if (rc != CLI_EXIT_OK) {
        return rc;
    }
    if (rt->svc.ec2_describe_instances == NULL ||
        rt->svc.ec2_terminate_instances == NULL ||
        rt->svc.ec2_wait_terminated == NULL) {
        return instance_fail(rt, CLI_EXIT_USAGE, "EC2 services unavailable");
    }

    instance_err(rt, "stackctl: resolving project instances\n");
    {
        const char *const project_values[] = {rt->cfg.project};
        ec2_filter filter = {"tag:Project", project_values, 1};

        memset(&list, 0, sizeof list);
        rc = rt->svc.ec2_describe_instances(rt->svc.ec2, &filter, 1, &list);
        if (rc != 0) {
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot describe project instances");
        }
    }

    if (opts->instance_id != NULL) {
        const ec2_instance *target =
            instance_find(&list, opts->instance_id);

        if (target == NULL ||
            ec2_instance_tag(target, "Project") == NULL ||
            strcmp(ec2_instance_tag(target, "Project"), rt->cfg.project) != 0) {
            ec2_instance_list_free(&list);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "instance %s was not found or is not tagged Project=%s",
                opts->instance_id, rt->cfg.project);
        }
        if (!instance_state_terminable(target->state)) {
            char target_state[64];

            snprintf(target_state, sizeof target_state, "%s", target->state);
            ec2_instance_list_free(&list);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "instance %s is %s; there is nothing to terminate",
                opts->instance_id,
                target_state[0] != '\0' ? target_state : "unknown");
        }
        snprintf(target_ip, sizeof target_ip, "%s", target->public_ip);
        snprintf(id_storage[id_count], sizeof id_storage[0], "%s",
                 target->instance_id);
        ids[id_count] = id_storage[id_count];
        id_count++;
    } else {
        for (size_t i = 0; i < list.count && id_count < 64; i++) {
            if (instance_state_terminable(list.items[i].state)) {
                snprintf(id_storage[id_count], sizeof id_storage[0], "%s",
                         list.items[i].instance_id);
                ids[id_count] = id_storage[id_count];
                id_count++;
            }
        }
    }
    ec2_instance_list_free(&list);

    if (id_count > 0) {
        ec2_terminate_result terminated;
        int timed_out = 0;

        instance_err(rt, "stackctl: terminating %zu instance(s):", id_count);
        for (size_t i = 0; i < id_count; i++) {
            instance_err(rt, " %s", ids[i]);
        }
        instance_err(rt, "\n");
        memset(&terminated, 0, sizeof terminated);
        rc = rt->svc.ec2_terminate_instances(rt->svc.ec2, ids, id_count,
                                             &terminated);
        ec2_terminate_result_free(&terminated);
        if (rc != 0) {
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "failed to terminate instances");
        }
        rc = wait_terminated_with_progress(rt, ids, id_count, &timed_out);
        if (rc != 0) {
            instance_err(rt,
                         "stackctl: failed while waiting for termination; "
                         "parking DDNS and forgetting host keys anyway\n");
            waiter_failed = 1;
        } else if (timed_out != 0) {
            instance_err(rt,
                         "stackctl: timed out waiting for instances to "
                         "terminate after %ds; parking DDNS and forgetting "
                         "host keys anyway\n",
                         TERMINATE_WAIT_BUDGET_SEC);
            waiter_failed = 1;
        }
    } else {
        instance_err(rt, "stackctl: no matching instances to terminate\n");
    }

    /*
     * --instance-id parks only when the record still points at that instance's
     * IP; the sweep always parks (including zero matches). After a waiter
     * failure the instance is still going away server-side, so park and forget
     * best-effort even though the verb reports exit 5.
     */
    if (opts->instance_id != NULL) {
        int snap = instance_dns_snapshot(rt, record_ip, sizeof record_ip, NULL);

        if (snap == 0 && target_ip[0] != '\0' &&
            strcmp(record_ip, target_ip) == 0) {
            exit_code = park_record(rt);
            if (exit_code != CLI_EXIT_OK) {
                if (!waiter_failed) {
                    return exit_code;
                }
                instance_warn(rt,
                              "DDNS park did not complete after a waiter "
                              "failure");
            } else {
                parked = true;
            }
        } else if (snap != 0 && snap != ENOENT) {
            if (!waiter_failed) {
                return instance_fail(
                    rt, CLI_EXIT_CLEANUP,
                    "cannot read the DDNS record to decide whether to park");
            }
            instance_warn(rt, "cannot read the DDNS record to park it");
        }
    } else {
        exit_code = park_record(rt);
        if (exit_code != CLI_EXIT_OK) {
            if (!waiter_failed) {
                return exit_code;
            }
            instance_warn(rt,
                          "DDNS park did not complete after a waiter failure");
        } else {
            parked = instance_ddns_configured(rt);
        }
    }

    forget_bindings(rt, ids, id_count);
    emit_result(rt, ids, id_count, parked);
    instance_audit(rt, "terminate", opts->instance_id != NULL
                                        ? opts->instance_id
                                        : "<sweep>",
                   waiter_failed ? "cleanup-incomplete" : "success");
    return waiter_failed ? CLI_EXIT_CLEANUP : CLI_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Production entry point                                                    */
/* ------------------------------------------------------------------------- */

int cli_cmd_terminate(cli_ctx *ctx) {
    instance_services svc;
    instance_runtime rt;
    terminate_options opts;
    cli_args args;
    int rc;

    if (ctx == NULL) {
        return CLI_EXIT_USAGE;
    }
    rc = cli_ctx_parse_args(ctx, terminate_option_specs, terminate_option_count,
                            &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "invalid terminate arguments");
    }
    opts.instance_id = cli_args_value(&args, "instance-id");

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
    rc = terminate_execute(&rt, &opts);
    instance_services_close(&svc);
    cli_args_free(&args);
    return rc;
}
