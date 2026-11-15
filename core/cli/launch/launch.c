/*
 * launch.c — `stackctl launch` (spec §4).
 *
 * Preflight (AMI, DDNS record + secret, OPERATOR_CIDR) → stack outputs →
 * RunInstances (spot/on-demand, instance-only tags, ClientToken + launch nonce)
 * → ready waiter → DDNS update + authoritative verify → host-key verification
 * (console fingerprints vs ssh-keyscan, TOFU only here) → known-hosts pin →
 * setup SSH session with the env contract → replacement of the previous
 * instance (unless --keep-old) → launch record.
 *
 * Failure path: terminate the new instance (unless --keep-on-failure) and
 * restore DNS per the restore-target rule; cleanup failure is exit 5, otherwise
 * the primary failure's class stands.
 */

#include "launch_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/ssh/ssh.h"

const cli_option_spec launch_option_specs[] = {
    {"arch", 0, 1, 0, "<amd64|arm64>", "launch architecture (required for ARCH=both)"},
    {"instance-type", 0, 1, 0, "<type>", "instance type (allowlist member)"},
    {"variant", 0, 1, 0, "<go|c>", "deployment manifest variant"},
    {"spot", 0, 0, 0, NULL, "request a spot instance"},
    {"no-spot", 0, 0, 0, NULL, "request an on-demand instance"},
    {"keep-on-failure", 0, 0, 0, NULL, "do not terminate on launch failure"},
    {"keep-old", 0, 0, 0, NULL, "skip replacing the previous instance"},
    {"instance-timeout", 0, 1, 0, "<sec>", "instance-ready waiter timeout"},
    {"ssh-timeout", 0, 1, 0, "<sec>", "SSH connect timeout"},
    {"setup-timeout", 0, 1, 0, "<sec>", "setup entrypoint timeout"},
};

const size_t launch_option_count =
    sizeof launch_option_specs / sizeof launch_option_specs[0];

#define LAUNCH_DEFAULT_INSTANCE_TIMEOUT 300
#define LAUNCH_DEFAULT_SSH_TIMEOUT 300
#define LAUNCH_DEFAULT_SETUP_TIMEOUT 1800

/* Append `'value'` with shell-safe single-quote escaping. */
static int append_quoted(char *out, size_t cap, size_t *used, const char *value) {
    if (*used + 1 < cap) {
        out[(*used)++] = '\'';
    }
    for (const char *cursor = value != NULL ? value : ""; *cursor != '\0'; cursor++) {
        if (*cursor == '\'') {
            const char *escaped = "'\\''";

            for (const char *e = escaped; *e != '\0'; e++) {
                if (*used + 1 >= cap) {
                    return ENAMETOOLONG;
                }
                out[(*used)++] = *e;
            }
        } else {
            if (*used + 1 >= cap) {
                return ENAMETOOLONG;
            }
            out[(*used)++] = *cursor;
        }
    }
    if (*used + 1 >= cap) {
        return ENAMETOOLONG;
    }
    out[(*used)++] = '\'';
    out[*used] = '\0';
    return 0;
}

static int append_text(char *out, size_t cap, size_t *used, const char *text) {
    size_t len = strlen(text);

    if (*used + len + 1 > cap) {
        return ENAMETOOLONG;
    }
    memcpy(out + *used, text, len);
    *used += len;
    out[*used] = '\0';
    return 0;
}

static int append_env(char *out, size_t cap, size_t *used, const char *key,
                      const char *value) {
    int rc = append_text(out, cap, used, key);

    if (rc == 0) {
        rc = append_text(out, cap, used, "=");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, used, value != NULL ? value : "");
    }
    if (rc == 0) {
        rc = append_text(out, cap, used, " ");
    }
    return rc;
}

static const char *known_hosts_path(instance_runtime *rt) {
    return rt->state != NULL ? state_known_hosts_path(rt->state) : "/dev/null";
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

/* Resolve the effective AMI for `arch` (pinned/ssm/baked, no fallbacks). */
static int resolve_ami(instance_runtime *rt, const cfn_stack *stack,
                       const char *arch, char *out, size_t cap) {
    const char *policy = rt->cfg.ami_policy;

    if (strcmp(policy, "pinned") == 0) {
        /* The stack is the only source of truth under a pin: never fall back
         * to config (config pins reach the stack only through deploy). */
        const char *value = cfn_stack_parameter(
            stack, strcmp(arch, "arm64") == 0 ? "AmiIdArm64" : "AmiIdAmd64");

        if (value == NULL || value[0] == '\0') {
            return ENOENT;
        }
        snprintf(out, cap, "%s", value);
        return 0;
    }
    {
        char name[INST_SSM_PARAM_MAX];
        ssm_parameter parameter;
        int rc;

        if (strcmp(policy, "baked") == 0) {
            snprintf(name, sizeof name, "/%s/ami/baked/latest", rt->cfg.project);
        } else {
            snprintf(name, sizeof name, "%s",
                     strcmp(arch, "arm64") == 0 ? rt->cfg.ami_ssm_arm64
                                                : rt->cfg.ami_ssm_amd64);
        }
        if (name[0] == '\0') {
            return ENOENT;
        }
        memset(&parameter, 0, sizeof parameter);
        rc = rt->svc.ssm_get_parameter(rt->svc.ssm, name, 0, &parameter);
        if (rc != 0) {
            return rc;
        }
        snprintf(out, cap, "%s", parameter.value != NULL ? parameter.value : "");
        ssm_parameter_free(&parameter);
        return out[0] != '\0' ? 0 : ENOENT;
    }
}

/* Terminate `id` and wait; returns 0 or EIO/ETIMEDOUT-class failure. */
static int terminate_and_wait(instance_runtime *rt, const char *const *ids,
                              size_t count, int *timed_out) {
    ec2_terminate_result result;
    int rc;

    if (rt->svc.ec2_terminate_instances == NULL ||
        rt->svc.ec2_wait_terminated == NULL) {
        return ENOSYS;
    }
    memset(&result, 0, sizeof result);
    rc = rt->svc.ec2_terminate_instances(rt->svc.ec2, ids, count, &result);
    ec2_terminate_result_free(&result);
    if (rc != 0) {
        return rc;
    }
    return rt->svc.ec2_wait_terminated(rt->svc.ec2, ids, count,
                                       rt->wait_attempts, rt->wait_interval,
                                       timed_out);
}

/*
 * Failure cleanup: terminate the new instance (unless kept) and restore DNS
 * (snapshot IP only while it is still a live instance IP, else park).
 */
static int launch_fail(instance_runtime *rt, const launch_options *opts,
                       const char *new_id, const char *snapshot_ip, int code) {
    int cleanup_failed = 0;

    if (new_id != NULL && !opts->keep_on_failure) {
        const char *ids[1] = {new_id};
        int timed_out = 0;

        if (terminate_and_wait(rt, ids, 1, &timed_out) != 0 || timed_out != 0) {
            cleanup_failed = 1;
            instance_err(rt,
                         "stackctl: could not confirm termination of %s; run "
                         "`stackctl terminate --instance-id %s`\n",
                         new_id, new_id);
        }
    }

    if (instance_ddns_configured(rt) && snapshot_ip != NULL) {
        char password[INST_PATH_MAX];
        char target[64];

        if (instance_ddns_password(rt, password, sizeof password) != 0) {
            cleanup_failed = 1;
        } else {
            const char *restore = "0.0.0.0";
            ec2_instance_list list;

            memset(&list, 0, sizeof list);
            if (rt->svc.ec2_describe_instances != NULL) {
                const char *const project_values[] = {rt->cfg.project};
                ec2_filter filter = {"tag:Project", project_values, 1};

                if (rt->svc.ec2_describe_instances(rt->svc.ec2, &filter, 1,
                                                   &list) == 0) {
                    restore = instance_restore_ip(snapshot_ip, &list);
                    ec2_instance_list_free(&list);
                }
            }
            snprintf(target, sizeof target, "%s", restore);
            {
                bool updated = false;

                if (instance_ddns_set(rt, password, target, &updated) != 0 ||
                    !updated ||
                    instance_dns_verify(rt, target, rt->dns_attempts,
                                        rt->dns_interval) != 0) {
                    cleanup_failed = 1;
                    instance_err(rt,
                                 "stackctl: could not restore the DDNS record "
                                 "to %s\n",
                                 target);
                }
            }
            memset(password, 0, sizeof password);
        }
    }

    return cleanup_failed ? CLI_EXIT_CLEANUP : code;
}

/* True when `token` is a `-`/`.`/`_`/`/`-delimited component of `text`. */
static int token_in(const char *text, const char *token) {
    const char *cursor = text;

    if (text == NULL || token == NULL || token[0] == '\0') {
        return 0;
    }
    while (*cursor != '\0') {
        const char *start;
        size_t len;

        while (*cursor != '\0' &&
               (*cursor == '-' || *cursor == '.' || *cursor == '_' ||
                *cursor == '/')) {
            cursor++;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != '-' && *cursor != '.' &&
               *cursor != '_' && *cursor != '/') {
            cursor++;
        }
        len = (size_t)(cursor - start);
        if (len == strlen(token) && strncmp(start, token, len) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * The setup environment must always carry a non-empty variant: the explicit
 * --variant wins, otherwise derive it from the selected member (go/c), with
 * "default" as the last-resort label.
 */
static void derive_variant(const char *member, const char *flag, char *out,
                           size_t cap) {
    if (flag != NULL && flag[0] != '\0') {
        snprintf(out, cap, "%s", flag);
        return;
    }
    if (token_in(member, "go")) {
        snprintf(out, cap, "%s", "go");
        return;
    }
    if (token_in(member, "c")) {
        snprintf(out, cap, "%s", "c");
        return;
    }
    snprintf(out, cap, "%s", "default");
}

/*
 * Resolve the release member for this launch: fetch the manifest from S3,
 * verify its sha against the stack's `stackctl:release-sha` tag, then select
 * the member + sha for the arch/variant. Returns 0, ENOENT (missing manifest or
 * member -> verification failure), EINVAL/EAMBIGUOUS choice (usage), EBADMSG
 * (manifest sha mismatch -> verification failure), or another errno.
 */
static int resolve_release(instance_runtime *rt, const cfn_stack *stack,
                           const char *arch, const char *variant,
                           char *tag_out, size_t tag_cap, char *member_out,
                           size_t member_cap, char *sha_out, size_t sha_cap,
                           char *member_sha_out, size_t member_sha_cap,
                           char *choices_out, size_t choices_cap) {
    const char *tag = cfn_stack_tag(stack, "stackctl:release-tag");
    const char *sha = cfn_stack_tag(stack, "stackctl:release-sha");
    const char *bucket = cfn_stack_output(stack, "ArtifactBucketName");
    char key[512];
    char *manifest = NULL;
    size_t len = 0;
    int rc;

    if (tag == NULL || tag[0] == '\0' || sha == NULL || sha[0] == '\0' ||
        bucket == NULL || bucket[0] == '\0') {
        return ENOENT;
    }
    if (rt->svc.s3_get_object == NULL) {
        return ENOSYS;
    }
    if (snprintf(key, sizeof key, "releases/%s/release-manifest.txt", tag) >=
        (int)sizeof key) {
        return ENAMETOOLONG;
    }
    rc = rt->svc.s3_get_object(rt->svc.s3, bucket, key, &manifest, &len);
    if (rc != 0) {
        return rc;
    }
    rc = s3_sha256_verify(manifest, len, sha);
    if (rc != 0) {
        free(manifest);
        return rc;
    }
    rc = instance_manifest_select(manifest, variant, arch, member_out,
                                  member_cap, member_sha_out, member_sha_cap,
                                  choices_out, choices_cap);
    free(manifest);
    if (rc != 0) {
        return rc;
    }
    snprintf(tag_out, tag_cap, "%s", tag);
    snprintf(sha_out, sha_cap, "%s", sha);
    return 0;
}

/*
 * Build the remote wrapper: stage the selected member from S3 (bounded retry),
 * verify it against the operator-verified sha, run the entrypoint, then print
 * the STACKCTL_RC sentinel. On success the staging dir is removed; on failure
 * the real status is retained in /run/stackctl-setup.<nonce>/rc so the
 * reconnect-once reader can report it. Staging lives on tmpfs and is 0700.
 */
static int build_setup_script(char *out, size_t cap, const char *stage_dir,
                              const char *bucket, const char *tag,
                              const char *member, const char *member_sha,
                              const char *entrypoint) {
    char s3_url[1024];
    size_t used = 0;
    int rc = 0;

    if (snprintf(s3_url, sizeof s3_url, "s3://%s/releases/%s/%s", bucket, tag,
                 member) >= (int)sizeof s3_url) {
        return ENAMETOOLONG;
    }
    rc = append_text(out, cap, &used, "d=");
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, stage_dir);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used,
                         "\nsudo install -d -m 700 \"$d\"\n"
                         "ok=0\nn=0\n"
                         "while [ \"$n\" -lt 6 ]; do\n"
                         "  if sudo aws s3 cp ");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, s3_url);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used,
                         " \"$d\"/");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, member);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used,
                         "; then ok=1; break; fi\n"
                         "  n=$((n+1)); sleep 10\n"
                         "done\nrc=0\n"
                         "if [ \"$ok\" -ne 1 ]; then rc=1\n"
                         "elif ! printf '%s  %s\\n' ");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, member_sha);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used,
                         " \"$d\"/");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, member);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used,
                         " | sudo sha256sum --check - >/dev/null 2>&1; then "
                         "rc=3\nelse\n  ");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, entrypoint);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used,
                         " >\"$d/setup.log\" 2>&1\n"
                         "  rc=$?\nfi\n"
                         /* Surface the entrypoint's tail on the operator's
                          * stderr (the ssh child inherits it). */
                         "if [ -f \"$d/setup.log\" ]; then\n"
                         "  tail -n 150 \"$d/setup.log\" >&2\n"
                         "fi\n"
                         /* Success: remove the staging dir; the rc file is no
                          * longer needed because ssh returns 0. Failure: keep
                          * the rc file so the reconnect-once reader can report
                          * the real status after a transport-level 255. */
                         "if [ \"$rc\" -eq 0 ]; then\n"
                         "  sudo rm -rf \"$d\"\n"
                         "  echo \"STACKCTL_RC=0\"\n"
                         "  exit 0\n"
                         "fi\n"
                         "printf '%s\\n' \"$rc\" | sudo tee \"$d/rc\" "
                         ">/dev/null\n"
                         "echo \"STACKCTL_RC=$rc\"\nexit \"$rc\"");
    }
    return rc;
}

/* Build the setup command string passed as the remote ssh operand. */
static int build_setup_command(instance_runtime *rt, const cfn_stack *stack,
                               const char *arch, const char *variant,
                               const char *member, const char *member_sha,
                               const char *nonce, char *out, size_t cap) {
    char stage_dir[INST_PATH_MAX];
    char script[4096];
    char derived[INST_ARCH_MAX];
    const char *bucket = cfn_stack_output(stack, "ArtifactBucketName");
    const char *tag = cfn_stack_tag(stack, "stackctl:release-tag");
    size_t used = 0;
    int rc = 0;

    if (snprintf(stage_dir, sizeof stage_dir, "/run/stackctl-setup.%s", nonce) >=
            (int)sizeof stage_dir) {
        return ENAMETOOLONG;
    }
    derive_variant(member, variant, derived, sizeof derived);
    rc = build_setup_script(script, sizeof script, stage_dir, bucket, tag,
                            member, member_sha, rt->cfg.setup_entrypoint);

    if (rc == 0) {
        rc = append_text(out, cap, &used, "sudo env -u BASH_ENV ");
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_PROJECT", rt->cfg.project);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_REGION", rt->cfg.region);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_RELEASE_TAG", tag);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_MANIFEST_SHA",
                        cfn_stack_tag(stack, "stackctl:release-sha"));
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_MEMBER", member);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_MEMBER_SHA", member_sha);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_ARCH", arch);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_VARIANT", derived);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_STAGE_DIR", stage_dir);
    }
    if (rc == 0) {
        rc = append_env(out, cap, &used, "STACKCTL_BUCKET_ARTIFACT", bucket);
    }
    if (rc == 0) {
        const char *cert_bucket = cfn_stack_output(stack, "CertBucketName");

        /* An absent/empty output means the cert bucket module is disabled. */
        if (cert_bucket != NULL && cert_bucket[0] != '\0') {
            rc = append_env(out, cap, &used, "STACKCTL_BUCKET_CERT",
                            cert_bucket);
        }
    }
    if (rc == 0 && rt->cfg.ddns_onbox) {
        char path[INST_PATH_MAX];

        snprintf(path, sizeof path, "/etc/%s-ddns/password", rt->cfg.project);
        rc = append_env(out, cap, &used, "STACKCTL_DDNS_PASSWORD_FILE", path);
    }
    if (rc == 0) {
        rc = append_text(out, cap, &used, "bash -lc ");
    }
    if (rc == 0) {
        rc = append_quoted(out, cap, &used, script);
    }
    return rc;
}

/*
 * DDNS_ONBOX password delivery (spec §8, §9): the password was read from the
 * SSM SecureString operator-side; when the box must own it, scp it to a
 * user-writable remote staging path, then install it as a 0600 file at
 * /etc/<project>-ddns/password via sudo and remove the staging copy. The local
 * temp file is 0600 (mkstemp) and is always unlinked. Never argv: the secret
 * only travels through the temp file and the scp data channel.
 *
 * Returns CLI_EXIT_OK or the launch-failure class (7 for an ssh transport
 * failure, 4 otherwise); the caller owns termination/DNS cleanup.
 */
static int deliver_ddns_password(instance_runtime *rt, const char *ip,
                                 const char *instance_id, const char *nonce,
                                 int strict_yes, int timeout_sec) {
    char password[INST_PATH_MAX];
    char target[INST_PATH_MAX];
    char remote_tmp[INST_PATH_MAX];
    char local_tmp[64];
    char destination[INST_PATH_MAX + 64];
    char command[INST_PATH_MAX * 3];
    sshc_options ssh_opts;
    const char *scp_operands[2];
    const char *install_operands[2];
    char **argv = NULL;
    size_t command_used = 0;
    int fd = -1;
    int remote_rc = 0;
    int rc;

    memset(password, 0, sizeof password);
    if (snprintf(target, sizeof target, "/etc/%s-ddns/password",
                 rt->cfg.project) >= (int)sizeof target) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "DDNS password path is too long");
    }
    if (snprintf(remote_tmp, sizeof remote_tmp, "/tmp/.stackctl-ddns-%s",
                 nonce) >= (int)sizeof remote_tmp) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "DDNS staging path is too long");
    }
    if (snprintf(destination, sizeof destination, "%s:%s", ip, remote_tmp) >=
        (int)sizeof destination) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "DDNS scp destination is too long");
    }
    rc = instance_ddns_password(rt, password, sizeof password);
    if (rc != 0) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot read the DDNS password for on-box "
                             "delivery");
    }

    snprintf(local_tmp, sizeof local_tmp, "/tmp/stackctl-ddns-XXXXXX");
    fd = mkstemp(local_tmp);
    if (fd < 0) {
        memset(password, 0, sizeof password);
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot create the local DDNS password temp file");
    }
    {
        size_t len = strlen(password);
        size_t written = 0;

        while (written < len) {
            ssize_t chunk = write(fd, password + written, len - written);

            if (chunk > 0) {
                written += (size_t)chunk;
                continue;
            }
            if (chunk < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        rc = written == len && close(fd) == 0 ? 0 : EIO;
        fd = -1;
    }
    memset(password, 0, sizeof password);
    if (rc != 0) {
        (void)unlink(local_tmp);
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot write the local DDNS password temp file");
    }

    memset(&ssh_opts, 0, sizeof ssh_opts);
    ssh_opts.identity = rt->cfg.ssh_identity;
    ssh_opts.known_hosts = known_hosts_path(rt);
    ssh_opts.instance_id = instance_id;
    ssh_opts.strict_yes = strict_yes;
    ssh_opts.port = rt->cfg.ssh_port;
    ssh_opts.user = rt->cfg.ssh_user;
    ssh_opts.server_alive_interval = 15;
    ssh_opts.server_alive_count_max = 3;

    scp_operands[0] = local_tmp;
    scp_operands[1] = destination;
    rc = sshc_build_argv(SSHC_KIND_SCP, &ssh_opts, scp_operands, 2, &argv);
    if (rc != 0 || rt->svc.scp_exec == NULL) {
        sshc_argv_free(argv);
        (void)unlink(local_tmp);
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot prepare the DDNS password transfer");
    }
    rc = rt->svc.scp_exec(argv, timeout_sec, NULL, &remote_rc);
    sshc_argv_free(argv);
    (void)unlink(local_tmp);
    if (rc == ENOTCONN) {
        return instance_fail(
            rt, CLI_EXIT_SSH,
            "SSH transport failure delivering the DDNS password; verify your "
            "current public IP is within OPERATOR_CIDR (`stackctl status` "
            "checks this)");
    }
    if (rc != 0 || remote_rc != 0) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot deliver the DDNS password to %s", ip);
    }

    rc = append_text(command, sizeof command, &command_used,
                     "umask 077; sudo install -D -m 600 ");
    if (rc == 0) {
        rc = append_quoted(command, sizeof command, &command_used, remote_tmp);
    }
    if (rc == 0) {
        rc = append_text(command, sizeof command, &command_used, " ");
    }
    if (rc == 0) {
        rc = append_quoted(command, sizeof command, &command_used, target);
    }
    if (rc == 0) {
        rc = append_text(command, sizeof command, &command_used, " && rm -f ");
    }
    if (rc == 0) {
        rc = append_quoted(command, sizeof command, &command_used, remote_tmp);
    }
    if (rc != 0) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "DDNS password install command is too long");
    }

    install_operands[0] = ip;
    install_operands[1] = command;
    rc = sshc_build_argv(SSHC_KIND_SSH, &ssh_opts, install_operands, 2, &argv);
    if (rc != 0 || rt->svc.ssh_exec == NULL) {
        sshc_argv_free(argv);
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot prepare the DDNS password install");
    }
    rc = rt->svc.ssh_exec(argv, timeout_sec, NULL, &remote_rc);
    sshc_argv_free(argv);
    if (rc == ENOTCONN) {
        return instance_fail(
            rt, CLI_EXIT_SSH,
            "SSH transport failure installing the DDNS password; verify your "
            "current public IP is within OPERATOR_CIDR (`stackctl status` "
            "checks this)");
    }
    if (rc != 0 || remote_rc != 0) {
        return instance_fail(rt, CLI_EXIT_LAUNCH,
                             "cannot install the DDNS password at %s", target);
    }
    return CLI_EXIT_OK;
}

int launch_execute(instance_runtime *rt, const launch_options *opts) {
    cfn_stack_list stacks;
    const cfn_stack *stack = NULL;
    ec2_image_list images;
    char arch[INST_ARCH_MAX] = {0};
    const char *why = NULL;
    char ami[INST_AMI_ID_MAX] = {0};
    char instance_type[EC2_TYPE_MAX] = {0};
    char root_device[EC2_TYPE_MAX] = {0};
    char fqdn[INST_FQDN_MAX] = {0};
    char snapshot_ip[64] = {0};
    char password[INST_PATH_MAX];
    char nonce[33];
    char client_token[65];
    ec2_run_result run_result;
    ec2_instance ready;
    char new_ip[EC2_IP_MAX] = {0};
    char release_tag[STATE_TAG_MAX] = {0};
    char release_sha[INST_SHA_MAX] = {0};
    char member[512] = {0};
    char member_sha[INST_SHA_MAX] = {0};
    char choices[1024] = {0};
    char replaced[STATE_REPLACED_MAX] = {0};
    size_t replaced_used = 0;
    int spot;
    int timed_out = 0;
    int rc;

    if (rt == NULL || opts == NULL) {
        return CLI_EXIT_USAGE;
    }
    memset(&stacks, 0, sizeof stacks);
    memset(&images, 0, sizeof images);
    memset(&run_result, 0, sizeof run_result);
    memset(&ready, 0, sizeof ready);
    memset(password, 0, sizeof password);

    if (rt->cfg.project[0] == '\0') {
        return instance_fail(rt, CLI_EXIT_USAGE, "missing project");
    }
    /*
     * Local tool preflight: host-key pinning requires ssh-keyscan. Fail before
     * any AWS call or spend rather than midway through the launch.
     */
    if (rt->svc.tool_available != NULL &&
        !rt->svc.tool_available("ssh-keyscan")) {
        return instance_fail(
            rt, CLI_EXIT_USAGE,
            "ssh-keyscan not found on PATH; install the OpenSSH client tools "
            "(host-key pinning requires ssh-keyscan)");
    }

    /* Identity guard: never spend or mutate as the wrong project identity. */
    rc = instance_identity_guard(rt);
    if (rc != CLI_EXIT_OK) {
        return rc;
    }

    /* Infra stack outputs (missing stack = hard error, run deploy first). */
    {
        char stack_name[INST_PROJECT_MAX + 16];

        if (rt->svc.cfn_describe_stacks == NULL) {
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "CloudFormation unavailable");
        }
        snprintf(stack_name, sizeof stack_name, "%s-infra", rt->cfg.project);
        rc = rt->svc.cfn_describe_stacks(rt->svc.cfn, rt->cfg.region,
                                         stack_name, &stacks);
        if (rc == ENOENT || stacks.count == 0) {
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "infra stack %s not found; run `stackctl "
                                 "deploy` first",
                                 stack_name);
        }
        if (rc != 0) {
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot describe the infra stack");
        }
        stack = &stacks.items[0];
    }

    if (cfn_stack_output(stack, "SubnetId") == NULL ||
        cfn_stack_output(stack, "SecurityGroupId") == NULL ||
        cfn_stack_output(stack, "InstanceProfileName") == NULL) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "infra stack is missing required outputs");
    }

    /* Arch + AMI preflight. */
    if (instance_select_arch(rt->cfg.arch, opts->arch, arch, sizeof arch,
                             &why) != 0) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE, "%s",
                             why != NULL ? why : "invalid --arch");
    }
    rc = resolve_ami(rt, stack, arch, ami, sizeof ami);
    if (rc == ENOENT) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "no effective AMI for %s; run deploy first", arch);
    }
    if (rc != 0) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_AWS,
                             "cannot resolve the AMI for %s", arch);
    }
    {
        const char *ami_ids[1] = {ami};

        rc = rt->svc.ec2_describe_images(rt->svc.ec2, ami_ids, 1, &images);
        if (rc != 0) {
            ec2_image_list_free(&images);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot describe AMI %s", ami);
        }
        if (images.count == 0) {
            ec2_image_list_free(&images);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "AMI %s does not exist in %s", ami,
                                 rt->cfg.region);
        }
        snprintf(root_device, sizeof root_device, "%s",
                 images.items[0].root_device_name);
        ec2_image_list_free(&images);
    }

    if (instance_resolve_type(&rt->cfg, arch, opts->instance_type,
                              instance_type, sizeof instance_type) != 0) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "instance type is not in the %s allowlist", arch);
    }

    /*
     * Release identity: fetch + verify the manifest against the stack tag and
     * select the member for this arch/variant. This happens before any spend.
     */
    rc = resolve_release(rt, stack, arch, opts->variant, release_tag,
                         sizeof release_tag, member, sizeof member, release_sha,
                         sizeof release_sha, member_sha, sizeof member_sha,
                         choices, sizeof choices);
    if (rc == ENOENT) {
        cfn_stack_list_free(&stacks);
        return instance_fail(
            rt, CLI_EXIT_VERIFY,
            "release manifest/member for %s is missing from the artifact "
            "bucket; redeploy the release",
            arch);
    }
    if (rc == EBADMSG) {
        cfn_stack_list_free(&stacks);
        return instance_fail(
            rt, CLI_EXIT_VERIFY,
            "release manifest sha does not match stackctl:release-sha; "
            "redeploy or roll back");
    }
    if (rc == EINVAL) {
        cfn_stack_list_free(&stacks);
        return instance_fail(
            rt, CLI_EXIT_USAGE,
            "release manifest member for %s is ambiguous (choices: %s); pass "
            "--variant",
            arch, choices[0] != '\0' ? choices : "unknown");
    }
    if (rc != 0) {
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_AWS,
                             "cannot resolve the release manifest");
    }

    /* DDNS preflight: record present + secret readable; OPERATOR_CIDR set. */
    if (instance_ddns_configured(rt)) {
        bool exists = false;

        if (rt->svc.dns_record_exists != NULL &&
            rt->svc.dns_record_exists(rt->cfg.ddns_domain, rt->cfg.ddns_host,
                                      &exists) != 0) {
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot check the DDNS record");
        }
        if (!exists) {
            cfn_stack_list_free(&stacks);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "DDNS A record %s.%s is missing; create the A+Dynamic DNS "
                "record first",
                rt->cfg.ddns_host, rt->cfg.ddns_domain);
        }
        rc = instance_ddns_password(rt, password, sizeof password);
        if (rc == ENOENT) {
            cfn_stack_list_free(&stacks);
            return instance_fail(
                rt, CLI_EXIT_USAGE,
                "DDNS SSM parameter /%s/ddns/password is missing", rt->cfg.project);
        }
        if (rc != 0) {
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS,
                                 "cannot read the DDNS SSM parameter");
        }
        if (instance_dns_snapshot(rt, snapshot_ip, sizeof snapshot_ip, NULL) !=
            0) {
            memset(password, 0, sizeof password);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_USAGE,
                                 "cannot snapshot the DDNS A record");
        }
        if (instance_fqdn(rt->cfg.ddns_host, rt->cfg.ddns_domain, fqdn,
                          sizeof fqdn) != 0) {
            memset(password, 0, sizeof password);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_USAGE, "invalid DDNS host/domain");
        }
    } else {
        snprintf(fqdn, sizeof fqdn, "%s", rt->cfg.project);
    }
    if (rt->cfg.operator_cidr[0] == '\0') {
        memset(password, 0, sizeof password);
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE,
                             "SSH impossible; set OPERATOR_CIDR and redeploy");
    }

    spot = opts->spot_set < 0 ? rt->cfg.spot_default : opts->spot_set;
    rc = instance_nonce(nonce);
    if (rc != 0 || instance_client_token(rt->cfg.project, nonce, client_token) != 0) {
        memset(password, 0, sizeof password);
        cfn_stack_list_free(&stacks);
        return instance_fail(rt, CLI_EXIT_USAGE, "cannot generate launch nonce");
    }

    /* RunInstances. */
    {
        ec2_run_spec spec;

        memset(&spec, 0, sizeof spec);
        spec.ami_id = ami;
        spec.instance_type = instance_type;
        spec.key_name = rt->cfg.key_name;
        spec.subnet_id = cfn_stack_output(stack, "SubnetId");
        spec.security_group_id = cfn_stack_output(stack, "SecurityGroupId");
        spec.instance_profile_name =
            cfn_stack_output(stack, "InstanceProfileName");
        spec.client_token = client_token;
        spec.project = rt->cfg.project;
        spec.name = fqdn;
        spec.launch_nonce = nonce;
        spec.root_device_name = root_device;
        spec.root_volume_type =
            rt->cfg.root_volume_type[0] != '\0' ? rt->cfg.root_volume_type
                                                : "gp3";
        spec.root_volume_size_gb = rt->cfg.root_volume_size_gb;
        spec.spot = spot;

        rc = rt->svc.ec2_run_instances(rt->svc.ec2, &spec, &run_result);
        if (rc != 0) {
            memset(password, 0, sizeof password);
            cfn_stack_list_free(&stacks);
            return instance_fail(rt, CLI_EXIT_AWS, "RunInstances failed");
        }
    }

    /* Ready waiter. */
    rc = rt->svc.ec2_wait_running(rt->svc.ec2, run_result.instance_id,
                                  rt->wait_attempts, rt->wait_interval, &ready,
                                  &timed_out);
    if (rc != 0 || timed_out != 0) {
        int status = rc == 0 ? CLI_EXIT_LAUNCH : CLI_EXIT_AWS;
        int result;

        memset(password, 0, sizeof password);
        cfn_stack_list_free(&stacks);
        result = launch_fail(rt, opts, run_result.instance_id, snapshot_ip,
                             status);
        return result;
    }
    snprintf(new_ip, sizeof new_ip, "%s",
             ready.public_ip[0] != '\0' ? ready.public_ip
                                        : run_result.public_ip);

    /* DDNS update + verify. */
    if (instance_ddns_configured(rt)) {
        bool updated = false;

        if (instance_ddns_set(rt, password, new_ip, &updated) != 0 ||
            !updated ||
            instance_dns_verify(rt, new_ip, rt->dns_attempts,
                                rt->dns_interval) != 0) {
            int result;

            memset(password, 0, sizeof password);
            cfn_stack_list_free(&stacks);
            result = launch_fail(rt, opts, run_result.instance_id, snapshot_ip,
                                 CLI_EXIT_LAUNCH);
            return result;
        }
    }
    memset(password, 0, sizeof password);

    /* Host-key verification. */
    {
        char *console = NULL;
        char *key_line = NULL;
        char fingerprint[INST_FINGERPRINT_MAX] = {0};
        char prints[8][INST_FINGERPRINT_MAX];
        size_t print_count = 0;
        int strict_yes = 1;
        int failure = 0;
        int attempts = rt->ssh_attempts > 0 ? rt->ssh_attempts : 1;
        int console_error = 0;

        /*
         * Bounded GetConsoleOutput poll (~--ssh-timeout): cloud-init may take
         * minutes to publish the host-key fingerprint block. A persistent AWS
         * error is exit 2; an empty-but-successful console is the TOFU case.
         */
        for (int attempt = 0; attempt < attempts; attempt++) {
            free(console);
            console = NULL;
            print_count = 0;
            rc = rt->svc.ec2_get_console_output(
                rt->svc.ec2, run_result.instance_id, &console);
            if (rc == 0) {
                console_error = 0;
                (void)instance_console_fingerprints(
                    console != NULL ? console : "", prints, 8, &print_count);
                if (print_count > 0) {
                    break;
                }
            } else {
                console_error = 1;
            }
            if (attempt + 1 < attempts) {
                sleep_seconds(rt->ssh_interval);
            }
        }
        if (print_count == 0 && console_error) {
            failure = CLI_EXIT_AWS;
        }

        /* ssh-keyscan is retried within the same timeout budget. */
        if (failure == 0) {
            for (int attempt = 0; attempt < attempts; attempt++) {
                free(key_line);
                key_line = NULL;
                rc = rt->svc.keyscan(new_ip, rt->cfg.ssh_port, &key_line);
                if (rc == 0 && key_line != NULL) {
                    break;
                }
                if (attempt + 1 < attempts) {
                    sleep_seconds(rt->ssh_interval);
                }
            }
            if (key_line == NULL ||
                instance_key_fingerprint(key_line, fingerprint,
                                         sizeof fingerprint) != 0) {
                failure = CLI_EXIT_SSH;
            }
        }
        if (failure == 0) {
            if (print_count > 0) {
                int match = 0;

                for (size_t i = 0; i < print_count; i++) {
                    if (strcmp(prints[i], fingerprint) == 0) {
                        match = 1;
                    }
                }
                if (!match) {
                    failure = CLI_EXIT_VERIFY;
                }
            } else {
                strict_yes = 0; /* single-connection TOFU fallback */
                instance_warn(rt,
                              "console host-key fingerprints unavailable; "
                              "trusting the first scanned key (TOFU)");
            }
        }
        if (failure == 0 &&
            rt->svc.kh_pin(known_hosts_path(rt), run_result.instance_id,
                           key_line) != 0) {
            failure = CLI_EXIT_VERIFY;
        }
        if (failure == 0 && rt->state != NULL) {
            kh_binding binding;

            memset(&binding, 0, sizeof binding);
            snprintf(binding.instance_id, sizeof binding.instance_id, "%s",
                     run_result.instance_id);
            snprintf(binding.host_key, sizeof binding.host_key, "%s",
                     fingerprint);
            snprintf(binding.fqdn, sizeof binding.fqdn, "%s", fqdn);
            snprintf(binding.ip, sizeof binding.ip, "%s", new_ip);
            if (state_binding_put(rt->state, &binding) != 0) {
                failure = CLI_EXIT_VERIFY; /* same id + changed key = EPERM */
            }
        }
        free(console);
        free(key_line);
        if (failure != 0) {
            int result;

            cfn_stack_list_free(&stacks);
            result = launch_fail(rt, opts, run_result.instance_id, snapshot_ip,
                                 failure);
            return result;
        }

        /*
         * DDNS_ONBOX: deliver the SSM-read password to the instance only now
         * that the host key is pinned and the connection is authenticated.
         */
        if (rt->cfg.ddns_onbox) {
            int delivered = deliver_ddns_password(
                rt, new_ip, run_result.instance_id, nonce, strict_yes,
                opts->ssh_timeout > 0 ? opts->ssh_timeout
                                      : LAUNCH_DEFAULT_SSH_TIMEOUT);

            if (delivered != CLI_EXIT_OK) {
                cfn_stack_list_free(&stacks);
                return launch_fail(rt, opts, run_result.instance_id,
                                   snapshot_ip, delivered);
            }
        }

        /* Setup SSH session. */
        {
            char command[4096];
            char rc_path[INST_PATH_MAX];
            char rc_command[INST_PATH_MAX + 32];
            sshc_options ssh_opts;
            const char *operands[2];
            const char *reconnect_operands[2];
            char **argv = NULL;
            char **reconnect_argv = NULL;
            int remote_rc = 0;
            int ssh_rc;

            if (build_setup_command(rt, stack, arch, opts->variant, member,
                                    member_sha, nonce, command,
                                    sizeof command) != 0) {
                cfn_stack_list_free(&stacks);
                return launch_fail(rt, opts, run_result.instance_id,
                                   snapshot_ip, CLI_EXIT_USAGE);
            }
            snprintf(rc_path, sizeof rc_path, "/run/stackctl-setup.%s/rc",
                     nonce);
            snprintf(rc_command, sizeof rc_command, "sudo cat '%s'", rc_path);
            memset(&ssh_opts, 0, sizeof ssh_opts);
            ssh_opts.identity = rt->cfg.ssh_identity;
            ssh_opts.known_hosts = known_hosts_path(rt);
            ssh_opts.instance_id = run_result.instance_id;
            ssh_opts.strict_yes = strict_yes;
            ssh_opts.port = rt->cfg.ssh_port;
            ssh_opts.user = rt->cfg.ssh_user;
            ssh_opts.server_alive_interval = 15;
            ssh_opts.server_alive_count_max = 3;

            operands[0] = new_ip;
            operands[1] = command;
            if (sshc_build_argv(SSHC_KIND_SSH, &ssh_opts, operands, 2,
                                &argv) != 0) {
                cfn_stack_list_free(&stacks);
                return launch_fail(rt, opts, run_result.instance_id,
                                   snapshot_ip, CLI_EXIT_USAGE);
            }
            reconnect_operands[0] = new_ip;
            reconnect_operands[1] = rc_command;
            if (sshc_build_argv(SSHC_KIND_SSH, &ssh_opts, reconnect_operands,
                                2, &reconnect_argv) != 0) {
                sshc_argv_free(argv);
                cfn_stack_list_free(&stacks);
                return launch_fail(rt, opts, run_result.instance_id,
                                   snapshot_ip, CLI_EXIT_USAGE);
            }
            {
                sshc_sentinel_spec sentinel = {
                    .prefix = "STACKCTL_RC=",
                    .remote_rc_path = rc_path,
                    .reconnect_argv = reconnect_argv,
                };

                ssh_rc = rt->svc.ssh_exec(
                    argv, opts->setup_timeout > 0 ? opts->setup_timeout
                                                   : LAUNCH_DEFAULT_SETUP_TIMEOUT,
                    &sentinel, &remote_rc);
            }
            sshc_argv_free(argv);
            sshc_argv_free(reconnect_argv);
            if (ssh_rc == ENOTCONN) {
                cfn_stack_list_free(&stacks);
                return launch_fail(
                    rt, opts, run_result.instance_id, snapshot_ip,
                    CLI_EXIT_SSH);
            }
            if (ssh_rc != 0) {
                cfn_stack_list_free(&stacks);
                return launch_fail(rt, opts, run_result.instance_id,
                                   snapshot_ip, CLI_EXIT_SSH);
            }
            if (remote_rc != 0) {
                int setup_failure = remote_rc == CLI_EXIT_VERIFY
                                        ? CLI_EXIT_VERIFY
                                        : CLI_EXIT_LAUNCH;

                instance_err(rt,
                             "stackctl: setup entrypoint failed with status "
                             "%d\n",
                             remote_rc);
                cfn_stack_list_free(&stacks);
                return launch_fail(rt, opts, run_result.instance_id,
                                   snapshot_ip, setup_failure);
            }
        }
    }

    /* Post-launch reconciliation: terminate extra same-nonce instances. */
    if (rt->svc.ec2_describe_instances != NULL) {
        ec2_instance_list all;

        memset(&all, 0, sizeof all);
        {
            const char *const project_values[] = {rt->cfg.project};
            ec2_filter filter = {"tag:Project", project_values, 1};

            if (rt->svc.ec2_describe_instances(rt->svc.ec2, &filter, 1,
                                               &all) == 0) {
                for (size_t i = 0; i < all.count; i++) {
                    const char *other_nonce =
                        ec2_instance_tag(&all.items[i],
                                         "stackctl:launch-nonce");

                    if (other_nonce != NULL &&
                        strcmp(other_nonce, nonce) == 0 &&
                        strcmp(all.items[i].instance_id,
                               run_result.instance_id) != 0) {
                        const char *ids[1] = {all.items[i].instance_id};
                        int extra_timeout = 0;

                        (void)terminate_and_wait(rt, ids, 1, &extra_timeout);
                    }
                }
                ec2_instance_list_free(&all);
            }
        }
    }

    /* Replacement of the previous instance (unless --keep-old). */
    if (!opts->keep_old && rt->svc.ec2_describe_instances != NULL) {
        ec2_instance_list all;

        memset(&all, 0, sizeof all);
        {
            const char *const project_values[] = {rt->cfg.project};
            ec2_filter filter = {"tag:Project", project_values, 1};

            if (rt->svc.ec2_describe_instances(rt->svc.ec2, &filter, 1,
                                               &all) == 0) {
                const char *ids[64];
                size_t id_count = 0;

                for (size_t i = 0; i < all.count && id_count < 64; i++) {
                    if (strcmp(all.items[i].instance_id,
                               run_result.instance_id) == 0) {
                        continue;
                    }
                    if (!instance_state_active(all.items[i].state) &&
                        !instance_state_terminable(all.items[i].state)) {
                        continue;
                    }
                    ids[id_count++] = all.items[i].instance_id;
                }
                if (id_count > 0) {
                    int replace_timeout = 0;

                    if (terminate_and_wait(rt, ids, id_count, &replace_timeout) !=
                            0 ||
                        replace_timeout != 0) {
                        ec2_instance_list_free(&all);
                        cfn_stack_list_free(&stacks);
                        return instance_fail(
                            rt, CLI_EXIT_CLEANUP,
                            "failed to terminate the previous instance(s); "
                            "run `stackctl terminate`");
                    }
                    for (size_t i = 0; i < id_count; i++) {
                        const char *id = ids[i];
                        size_t need = strlen(id) + (replaced_used > 0 ? 2 : 1);

                        if (replaced_used + need < sizeof replaced) {
                            if (replaced_used > 0) {
                                replaced[replaced_used++] = ',';
                            }
                            memcpy(replaced + replaced_used, id, strlen(id));
                            replaced_used += strlen(id);
                            replaced[replaced_used] = '\0';
                        }
                        if (rt->state != NULL) {
                            (void)kh_forget(known_hosts_path(rt), id);
                            (void)state_binding_forget(rt->state, id);
                        }
                    }
                }
                ec2_instance_list_free(&all);
            }
        }
        (void)replaced;
    }

    /* Completed launch record (keyed by the nonce), including replaced ids. */
    if (rt->launch_record_append != NULL) {
        state_launch_record record;
        int record_rc;

        memset(&record, 0, sizeof record);
        snprintf(record.instance_id, sizeof record.instance_id, "%s",
                 run_result.instance_id);
        snprintf(record.nonce, sizeof record.nonce, "%s", nonce);
        snprintf(record.fqdn, sizeof record.fqdn, "%s", fqdn);
        snprintf(record.ip, sizeof record.ip, "%s", new_ip);
        snprintf(record.replaced, sizeof record.replaced, "%s", replaced);
        record_rc = rt->launch_record_append(rt->state, &record);
        if (record_rc != 0) {
            /*
             * Never report success with an unrecorded live instance: tear the
             * new instance down (and restore DNS) so no orphan is left behind.
             */
            instance_err(rt,
                         "stackctl: could not append the launch record (%s); "
                         "terminating %s to avoid an orphan\n",
                         strerror(record_rc), run_result.instance_id);
            cfn_stack_list_free(&stacks);
            return launch_fail(rt, opts, run_result.instance_id, snapshot_ip,
                               CLI_EXIT_CLEANUP);
        }
    }

    {
        char audit_args[STATE_REPLACED_MAX + STATE_INSTANCE_ID_MAX + 32];

        snprintf(audit_args, sizeof audit_args, "%s replaced=%s",
                 run_result.instance_id, replaced);
        instance_audit(rt, "launch", audit_args, "success");
    }

    if (rt->json) {
        instance_out(rt,
                     "{\"verb\":\"launch\",\"instance_id\":\"%s\","
                     "\"public_ip\":\"%s\",\"arch\":\"%s\",\"instance_type\":"
                     "\"%s\",\"spot\":%s}\n",
                     run_result.instance_id, new_ip, arch, instance_type,
                     spot ? "true" : "false");
    } else {
        instance_out(rt, "launched %s (%s) at %s\n", run_result.instance_id,
                     instance_type, new_ip);
    }
    cfn_stack_list_free(&stacks);
    return CLI_EXIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Production entry point                                                    */
/* ------------------------------------------------------------------------- */

int cli_cmd_launch(cli_ctx *ctx) {
    instance_services svc;
    instance_runtime rt;
    launch_options opts;
    cli_args args;
    int rc;
    int timeout = 0;

    if (ctx == NULL) {
        return CLI_EXIT_USAGE;
    }
    rc = cli_ctx_parse_args(ctx, launch_option_specs, launch_option_count,
                            &args);
    if (rc != 0) {
        return cli_fail(ctx, CLI_EXIT_USAGE, "invalid launch arguments");
    }
    memset(&opts, 0, sizeof opts);
    opts.arch = cli_args_value(&args, "arch");
    opts.instance_type = cli_args_value(&args, "instance-type");
    opts.variant = cli_args_value(&args, "variant");
    opts.keep_on_failure = cli_args_flag(&args, "keep-on-failure");
    opts.keep_old = cli_args_flag(&args, "keep-old");
    opts.spot_set = cli_args_flag(&args, "no-spot")
                        ? 0
                        : (cli_args_flag(&args, "spot") ? 1 : -1);
    if (cli_args_value(&args, "instance-timeout") != NULL &&
        instance_parse_seconds(cli_args_value(&args, "instance-timeout"),
                               &timeout) == 0) {
        opts.instance_timeout = timeout;
    }
    if (cli_args_value(&args, "ssh-timeout") != NULL &&
        instance_parse_seconds(cli_args_value(&args, "ssh-timeout"),
                               &timeout) == 0) {
        opts.ssh_timeout = timeout;
    }
    if (cli_args_value(&args, "setup-timeout") != NULL &&
        instance_parse_seconds(cli_args_value(&args, "setup-timeout"),
                               &timeout) == 0) {
        opts.setup_timeout = timeout;
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
    /* Keep runtime timing defaults aligned with the flag defaults. */
    if (opts.instance_timeout > 0) {
        rt.wait_attempts = opts.instance_timeout / 5 > 0
                               ? opts.instance_timeout / 5
                               : 1;
        rt.wait_interval = 5;
    }
    if (opts.ssh_timeout > 0) {
        rt.ssh_attempts = opts.ssh_timeout / 5 > 0 ? opts.ssh_timeout / 5 : 1;
        rt.ssh_interval = 5;
    }
    rc = launch_execute(&rt, &opts);
    instance_services_close(&svc);
    cli_args_free(&args);
    return rc;
}
