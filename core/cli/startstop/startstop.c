/*
 * startstop.c — `stackctl start` / `stackctl stop` (spec §4).
 *
 * Target selection: --instance-id (must be Project-tagged) or exactly one
 * running Project instance. Connects by public IP with HostKeyAlias and the
 * shared ssh argv contract. A missing binding re-verifies via GetConsoleOutput +
 * ssh-keyscan; TOFU only with --trust-new-host-key. The remote command is
 * `sudo systemctl start|stop <SERVICE_UNIT>`.
 */

#include "startstop_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/ssh/ssh.h"

const cli_option_spec startstop_option_specs[] = {
    {"instance-id", 0, 1, 0, "<id>",
     "act on exactly one Project-tagged instance"},
    {"trust-new-host-key", 0, 0, 0, NULL,
     "accept the scanned host key when no console fingerprint is available"},
};

const size_t startstop_option_count =
    sizeof startstop_option_specs / sizeof startstop_option_specs[0];

/* Retrieve the dedicated known-hosts store path (empty when state is absent). */
static const char *kh_store(instance_runtime *rt) {
    return rt->state != NULL ? state_known_hosts_path(rt->state)
                            : "/dev/null";
}

/* Re-run launch's console + ssh-keyscan verification and bind on a match. */
static int reverify_and_bind(instance_runtime *rt, const char *instance_id,
                             const char *ip, const char *fqdn,
                             int trust_new_host_key) {
    char *console = NULL;
    char *key_line = NULL;
    char fingerprint[INST_FINGERPRINT_MAX] = {0};
    char prints[8][INST_FINGERPRINT_MAX];
    size_t print_count = 0;
    int rc;
    int exit_code = CLI_EXIT_OK;

    if (rt->svc.ec2_get_console_output == NULL || rt->svc.keyscan == NULL ||
        rt->svc.kh_pin == NULL) {
        return instance_fail(rt, CLI_EXIT_SSH,
                             "host-key verification services unavailable");
    }
    rc = rt->svc.ec2_get_console_output(rt->svc.ec2, instance_id, &console);
    if (rc != 0) {
        return instance_fail(rt, CLI_EXIT_AWS,
                             "cannot fetch console output to verify the host "
                             "key");
    }
    rc = rt->svc.keyscan(ip, rt->cfg.ssh_port, &key_line);
    if (rc != 0 || key_line == NULL) {
        free(console);
        return instance_fail(
            rt, CLI_EXIT_SSH,
            "cannot scan the host key; verify the host key manually or pass "
            "--trust-new-host-key");
    }
    if (instance_key_fingerprint(key_line, fingerprint, sizeof fingerprint) !=
        0) {
        free(console);
        free(key_line);
        return instance_fail(rt, CLI_EXIT_SSH,
                             "scanned host key is malformed");
    }
    (void)instance_console_fingerprints(console != NULL ? console : "", prints,
                                        8, &print_count);
    if (print_count > 0) {
        int match = 0;

        for (size_t i = 0; i < print_count; i++) {
            if (strcmp(prints[i], fingerprint) == 0) {
                match = 1;
                break;
            }
        }
        if (!match) {
            free(console);
            free(key_line);
            return instance_fail(
                rt, CLI_EXIT_VERIFY,
                "host-key fingerprint mismatch for instance %s (possible "
                "compromise)",
                instance_id);
        }
    } else if (!trust_new_host_key) {
        free(console);
        free(key_line);
        return instance_fail(
            rt, CLI_EXIT_SSH,
            "no host-key binding; verify the host key manually or pass "
            "--trust-new-host-key");
    }

    rc = rt->svc.kh_pin(kh_store(rt), instance_id, key_line);
    if (rc == 0 && rt->state != NULL) {
        kh_binding binding;

        memset(&binding, 0, sizeof binding);
        snprintf(binding.instance_id, sizeof binding.instance_id, "%s",
                 instance_id);
        snprintf(binding.host_key, sizeof binding.host_key, "%s", fingerprint);
        snprintf(binding.fqdn, sizeof binding.fqdn, "%s",
                 fqdn != NULL && fqdn[0] != '\0' ? fqdn : instance_id);
        snprintf(binding.ip, sizeof binding.ip, "%s", ip);
        (void)state_binding_put(rt->state, &binding);
    }
    if (rc != 0) {
        exit_code = instance_fail(rt, CLI_EXIT_USAGE,
                                  "cannot pin the host key for %s",
                                  instance_id);
    }
    free(console);
    free(key_line);
    return exit_code;
}

int startstop_execute(instance_runtime *rt, const startstop_options *opts,
                      startstop_action action) {
    ec2_instance_list list;
    char instance_id[EC2_INSTANCE_ID_MAX] = {0};
    char ip[EC2_IP_MAX] = {0};
    char fqdn[STATE_FQDN_MAX] = {0};
    const char *action_name = action == STARTSTOP_STOP ? "stop" : "start";
    const char *store;
    int rc;

    if (rt == NULL || opts == NULL) {
        return CLI_EXIT_USAGE;
    }
    if (rt->cfg.service_unit[0] == '\0') {
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "SERVICE_UNIT is required for start/stop");
    }
    if (rt->cfg.operator_cidr[0] == '\0') {
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "SSH impossible; set OPERATOR_CIDR and redeploy");
    }
    /* Identity guard: re-assert the project identity before the state change. */
    rc = instance_identity_guard(rt);
    if (rc != CLI_EXIT_OK) {
        return rc;
    }
    if (rt->svc.ec2_describe_instances == NULL) {
        return instance_fail(rt, CLI_EXIT_USAGE, "EC2 unavailable");
    }

    memset(&list, 0, sizeof list);
    {
        const char *const project_values[] = {rt->cfg.project};
        ec2_filter filter = {"tag:Project", project_values, 1};

        rc = rt->svc.ec2_describe_instances(rt->svc.ec2, &filter, 1, &list);
        if (rc != 0) {
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot describe project instances");
        }
    }

    if (opts->instance_id != NULL) {
        const ec2_instance *target = instance_find(&list, opts->instance_id);

        if (target == NULL ||
            ec2_instance_tag(target, "Project") == NULL ||
            strcmp(ec2_instance_tag(target, "Project"), rt->cfg.project) != 0) {
            ec2_instance_list_free(&list);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "instance %s was not found or is not tagged Project=%s",
                opts->instance_id, rt->cfg.project);
        }
        snprintf(instance_id, sizeof instance_id, "%s", target->instance_id);
        snprintf(ip, sizeof ip, "%s", target->public_ip);
        snprintf(fqdn, sizeof fqdn, "%s",
                 ec2_instance_tag(target, "Name") != NULL
                     ? ec2_instance_tag(target, "Name")
                     : target->instance_id);
    } else {
        size_t running = 0;

        for (size_t i = 0; i < list.count; i++) {
            if (strcmp(list.items[i].state, "running") == 0) {
                running++;
            }
        }
        if (running == 0) {
            ec2_instance_list_free(&list);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "no running Project instance; launch or specify --instance-id");
        }
        if (running > 1) {
            char names[512] = {0};
            size_t used = 0;

            for (size_t i = 0; i < list.count; i++) {
                if (strcmp(list.items[i].state, "running") != 0) {
                    continue;
                }
                used += (size_t)snprintf(names + used, sizeof names - used,
                                         "%s%s", used > 0 ? ", " : "",
                                         list.items[i].instance_id);
                if (used >= sizeof names) {
                    break;
                }
            }
            ec2_instance_list_free(&list);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "multiple running instances (%s); choose one with "
                "--instance-id",
                names);
        }
        for (size_t i = 0; i < list.count; i++) {
            if (strcmp(list.items[i].state, "running") != 0) {
                continue;
            }
            snprintf(instance_id, sizeof instance_id, "%s",
                     list.items[i].instance_id);
            snprintf(ip, sizeof ip, "%s", list.items[i].public_ip);
            snprintf(fqdn, sizeof fqdn, "%s",
                     ec2_instance_tag(&list.items[i], "Name") != NULL
                         ? ec2_instance_tag(&list.items[i], "Name")
                         : list.items[i].instance_id);
        }
    }
    ec2_instance_list_free(&list);

    if (ip[0] == '\0') {
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "instance %s has no public IP", instance_id);
    }

    store = kh_store(rt);
    if (rt->svc.kh_bound == NULL || !rt->svc.kh_bound(store, instance_id)) {
        int verify = reverify_and_bind(rt, instance_id, ip, fqdn,
                                       opts->trust_new_host_key);

        if (verify != CLI_EXIT_OK) {
            return verify;
        }
    }

    {
        sshc_options ssh_opts;
        const char *operands[5];
        char **argv = NULL;
        int remote_rc = 0;

        memset(&ssh_opts, 0, sizeof ssh_opts);
        ssh_opts.identity = rt->cfg.ssh_identity;
        ssh_opts.known_hosts = store;
        ssh_opts.instance_id = instance_id;
        ssh_opts.strict_yes = 1;
        ssh_opts.port = rt->cfg.ssh_port;
        ssh_opts.user = rt->cfg.ssh_user;
        ssh_opts.server_alive_interval = 15;
        ssh_opts.server_alive_count_max = 3;

        operands[0] = ip;
        operands[1] = "sudo";
        operands[2] = "systemctl";
        operands[3] = action_name;
        operands[4] = rt->cfg.service_unit;

        rc = sshc_build_argv(SSHC_KIND_SSH, &ssh_opts, operands, 5, &argv);
        if (rc != 0) {
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "cannot build the ssh command line");
        }
        if (rt->svc.ssh_exec == NULL) {
            sshc_argv_free(argv);
            return instance_fail(rt, CLI_EXIT_SSH, "ssh unavailable");
        }
        /* First signal aborts the session; it takes the failure path (F9). */
        sshc_set_abort_hook(cli_abort_check, NULL);
        rc = rt->svc.ssh_exec(argv, 300, NULL, &remote_rc);
        sshc_set_abort_hook(NULL, NULL);
        sshc_argv_free(argv);
        if (rc == EINTR) {
            cli_signal_mark_consumed();
            return instance_fail(rt, CLI_EXIT_SSH,
                                 "SSH session interrupted by a signal");
        }
        if (rc == ENOTCONN) {
            return instance_fail(
                rt, CLI_EXIT_SSH,
                "SSH transport failure; verify your current public IP is "
                "within OPERATOR_CIDR (`stackctl status` checks this)");
        }
        if (rc != 0) {
            return instance_fail(rt, CLI_EXIT_SSH,
                                 "SSH session failed to complete");
        }
        if (remote_rc != 0) {
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "systemctl %s %s failed with status %d",
                                 action_name, rt->cfg.service_unit, remote_rc);
        }
    }

    if (rt->json) {
        instance_out(rt,
                     "{\"verb\":\"%s\",\"instance_id\":\"%s\",\"unit\":\"%s\","
                     "\"ok\":true}\n",
                     action_name, instance_id, rt->cfg.service_unit);
    } else {
        instance_out(rt, "%s: %s %s\n", action_name, rt->cfg.service_unit,
                     instance_id);
    }
    instance_audit(rt, action_name, instance_id, "success");
    return CLI_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Production entry points                                                   */
/* ------------------------------------------------------------------------- */

static int startstop_command(cli_ctx *ctx, startstop_action action) {
    instance_services svc;
    instance_runtime rt;
    startstop_options opts;
    cli_args args;
    int rc;

    if (ctx == NULL) {
        return CLI_EXIT_USAGE;
    }
    rc = cli_ctx_parse_args(ctx, startstop_option_specs,
                            startstop_option_count, &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "invalid arguments");
    }
    memset(&opts, 0, sizeof opts);
    opts.instance_id = cli_args_value(&args, "instance-id");
    opts.trust_new_host_key = cli_args_flag(&args, "trust-new-host-key");

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
    rc = startstop_execute(&rt, &opts, action);
    instance_services_close(&svc);
    cli_args_free(&args);
    return rc;
}

int cli_cmd_start(cli_ctx *ctx) {
    return startstop_command(ctx, STARTSTOP_START);
}

int cli_cmd_stop(cli_ctx *ctx) {
    return startstop_command(ctx, STARTSTOP_STOP);
}
