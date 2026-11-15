/*
 * ssh.h — exec `ssh(1)`/`scp(1)` with the controlled argv of spec §4.
 *
 * stackctl never links a libssh. One argv builder produces the exact option
 * set shared by ssh and scp (BatchMode, IdentitiesOnly, UpdateHostKeys=no,
 * ControlMaster=no, ControlPath=none, dedicated UserKnownHostsFile,
 * StrictHostKeyChecking, HostKeyAlias=instance-id, ServerAliveInterval/
 * CountMax, Port, User); sshc_exec runs it with a timeout, trusts the
 * `STACKCTL_RC=<n>` final-line sentinel over ssh's own exit code, applies the
 * exit-255 reconnect-once rule, and tears children down as a process group
 * (SIGTERM, 5 s, SIGKILL).
 *
 * All public symbols are prefixed `sshc_`; pure C, no network dependencies.
 * Error model (CONTRACT.md): 0 on success, else a non-zero errno-style code.
 * sshc_exec() returns 0 for any completed remote execution and reports the
 * remote status through *remote_rc; ENOTCONN means the transport failed and the
 * remote status is unknown.
 */

#ifndef STACKCTL_SSH_H
#define STACKCTL_SSH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SSHC_KIND_SSH = 0,
    SSHC_KIND_SCP = 1
} sshc_kind;

typedef struct sshc_options {
    const char *identity;      /* -i <path> */
    const char *known_hosts;   /* UserKnownHostsFile=<path> */
    const char *instance_id;   /* HostKeyAlias=<instance-id> */
    int strict_yes;            /* 1 = yes, 0 = accept-new (single TOFU) */
    int port;                  /* Port=<n>; must be > 0 */
    const char *user;          /* User=<name> */
    int server_alive_interval; /* <=0 => 15 */
    int server_alive_count_max;/* <=0 => 3 */
} sshc_options;

/*
 * Build a heap-allocated NULL-terminated argv.
 *
 *   kind          ssh (adds -T, no forced TTY) or scp.
 *   opts          the shared option set above.
 *   operands      kind-specific trailing operands: for ssh the connection host
 *                 (public IP) followed by the remote command; for scp the
 *                 source/destination operands. May be NULL when count is 0.
 *   operand_count number of operands.
 *   argv_out      receives the argv on success; free with sshc_argv_free().
 *
 * Returns 0, EINVAL on bad arguments, or ENOMEM.
 */
int sshc_build_argv(sshc_kind kind, const sshc_options *opts,
                    const char *const *operands, size_t operand_count,
                    char ***argv_out);

/* Free an argv returned by sshc_build_argv(). Safe on NULL. */
void sshc_argv_free(char **argv);

typedef struct sshc_sentinel_spec {
    const char *prefix;          /* e.g. "STACKCTL_RC=" */
    const char *remote_rc_path;  /* e.g. /run/stackctl-setup.<nonce>/rc */
    char *const *reconnect_argv; /* one-shot reader used after exit 255 */
} sshc_sentinel_spec;

/*
 * Optional abort hook, checked every SSHC_POLL_MS while a child runs. Returning
 * non-zero tears the child's process group down (SIGTERM, 5 s, SIGKILL) and makes
 * sshc_exec() return EINTR. Mirrors aws_set_abort_hook(); `user` is passed
 * through unchanged. Module-level state is deliberate: ssh runs one session per
 * verb.
 */
typedef int (*sshc_abort_fn)(void *user);
void sshc_set_abort_hook(sshc_abort_fn fn, void *user);

/*
 * Execute argv, capturing stdout for sentinel parsing.
 *
 *   argv        NULL-terminated command (e.g. from sshc_build_argv).
 *   timeout_sec wall-clock limit; <= 0 means no limit. On expiry the child
 *               process group receives SIGTERM, is given 5 s, then SIGKILL,
 *               and ETIMEDOUT is returned.
 *   sentinel    optional; when set, the last non-empty stdout line is parsed
 *               for `<prefix><n>` and that value wins over ssh's exit code.
 *   remote_rc   receives the remote exit status on success.
 *
 * If argv exits 255 without a sentinel and sentinel->reconnect_argv is set, it
 * is run once and its output parsed as the remote status (reading the on-box
 * rc file). Otherwise a 255 is a transport failure (ENOTCONN).
 */
int sshc_exec(char *const argv[], int timeout_sec,
              const sshc_sentinel_spec *sentinel, int *remote_rc);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_SSH_H */
