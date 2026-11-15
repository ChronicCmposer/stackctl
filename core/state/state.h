/*
 * state.h — on-disk persistence under `$XDG_STATE_HOME/stackctl/` (spec §2, §8).
 *
 * Owns the per-project/per-region state directory (0700), the exclusive
 * per-project/per-region lock, the instance→host binding map, launch records,
 * release history and the append-only operations log. All public symbols are
 * prefixed `state_`; the module is pure C with no network dependencies.
 *
 * Namespace: `$XDG_STATE_HOME/stackctl/<project>.<region>/` (default base
 * `$HOME/.local/state` when XDG_STATE_HOME is unset). The lock lives at
 * `$XDG_STATE_HOME/stackctl/<project>.<region>.lock`, outside the directory.
 *
 * Error model (CONTRACT.md): returns 0 on success, else a non-zero errno-style
 * code. Diagnostics go to stderr only.
 */

#ifndef STACKCTL_STATE_H
#define STACKCTL_STATE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STATE_INSTANCE_ID_MAX 64
#define STATE_HOST_KEY_MAX 512
#define STATE_FQDN_MAX 256
#define STATE_IP_MAX 64
#define STATE_NONCE_MAX 64
#define STATE_REPLACED_MAX 512
#define STATE_TAG_MAX 128

/* One FQDN→(instance, host key, IP) binding (spec §8 binding map). */
typedef struct kh_binding {
    char instance_id[STATE_INSTANCE_ID_MAX];
    char host_key[STATE_HOST_KEY_MAX];
    char fqdn[STATE_FQDN_MAX];
    char ip[STATE_IP_MAX];
} kh_binding;

/* One completed launch, keyed by the `stackctl:launch-nonce` tag. */
typedef struct state_launch_record {
    char instance_id[STATE_INSTANCE_ID_MAX];
    char nonce[STATE_NONCE_MAX];
    char fqdn[STATE_FQDN_MAX];
    char ip[STATE_IP_MAX];
    char replaced[STATE_REPLACED_MAX]; /* comma-separated instance ids, or "" */
} state_launch_record;

typedef struct state_store state_store;

/*
 * Open (creating if needed) the state namespace for project+region.
 * Creates `$XDG_STATE_HOME/stackctl/` and `<...>/<project>.<region>/` with mode
 * 0700. On success *out receives a heap-allocated store (state_close() it).
 * Empty names or names containing '/' or '\\' are EINVAL; a missing
 * XDG_STATE_HOME and HOME is ENOENT.
 */
int state_open(const char *project, const char *region, state_store **out);

/* Release a store returned by state_open(). Safe on NULL. */
void state_close(state_store *store);

/* Path/property accessors; owned by the store, valid until state_close(). */
const char *state_dir(const state_store *store);
const char *state_known_hosts_path(const state_store *store);
const char *state_bindings_path(const state_store *store);
const char *state_operations_log_path(const state_store *store);
const char *state_launch_records_path(const state_store *store);
const char *state_release_history_path(const state_store *store);
const char *state_lock_path(const state_store *store);
const char *state_project(const state_store *store);
const char *state_region(const state_store *store);

/*
 * Acquire the exclusive project lock (`flock(LOCK_EX)`). `timeout_sec` bounds
 * the wait; 0 means a single non-blocking attempt, negative waits forever.
 * Returns 0 on success, ETIMEDOUT on expiry, or another errno-style code.
 * The lock is process-global: state_unlock() releases it.
 */
int state_lock(const char *project, const char *region, int timeout_sec);

/* Release the lock held by state_lock(). Returns 0, or EBADF when none held. */
int state_unlock(void);

/*
 * Binding map (spec §8).
 *
 * state_binding_put() is the policy-carrying upsert:
 *   - same instance-id presenting a *different* host key is a hard error
 *     (EPERM) and leaves the stored binding untouched — never auto-healed;
 *   - a new instance-id claiming an FQDN previously bound to another instance
 *     *replaces* that binding with a warning on stderr.
 * state_binding_replace() performs the replacement unconditionally (callers
 * that already applied policy). Both reject empty/tab/newline fields (EINVAL).
 */
int state_binding_get(state_store *store, const char *instance_id,
                      kh_binding *out);
int state_binding_put(state_store *store, const kh_binding *binding);
int state_binding_replace(state_store *store, const kh_binding *binding);
int state_binding_forget(state_store *store, const char *instance_id);

/* Append one timestamped launch record (0600). */
int state_launch_record_append(state_store *store,
                               const state_launch_record *record);

/* Append one release tag to the release history (0600, append-only). */
int state_release_history_append(state_store *store, const char *tag);

/*
 * Append one audit-trail entry (0600, append-only, never secrets). `args` is
 * redacted: values of PASSWORD/SECRET/TOKEN-ish keys and the operand of
 * `--password` become `<redacted>` before writing.
 */
int state_operations_log_append(state_store *store, const char *verb,
                                const char *args, const char *outcome);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_STATE_H */
