/*
 * knownhosts.h — dedicated known-hosts store (spec §2, §4, §8).
 *
 * stackctl never touches `~/.ssh/known_hosts`. Launch scans the instance host
 * key and pins it into a dedicated per-project/per-region store; every ssh/scp
 * invocation points `UserKnownHostsFile` at that store and sets
 * `HostKeyAlias=<instance-id>`, so entries are addressed by instance-id (the
 * public IP is a connection target only). All public symbols are prefixed
 * `kh_`; pure C, no network dependencies.
 *
 * Store format is standard known_hosts with the alias as the first field:
 *     <instance-id> <key-type> <base64-key> [comment]
 *
 * Error model (CONTRACT.md): functions returning int use 0/errno-style codes.
 */

#ifndef STACKCTL_KNOWNHOSTS_H
#define STACKCTL_KNOWNHOSTS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pin `scanned_key_line` (an ssh-keyscan line: `<host> <key-type> <key>
 * [comment]`, or an already-aliased line) under `instance_id` in the store at
 * `store_path`.
 *
 * The host field is replaced with `instance_id`; the key material is kept. If
 * the same instance-id is already pinned with identical key material the call
 * is a no-op. A *different* key for the same instance-id is a hard error
 * (EPERM) and leaves the store untouched (spec §8: never auto-healed). The
 * store and its parent-visible entries are written atomically at mode 0600.
 *
 * Returns 0 on success, EINVAL on bad arguments, or an errno-style I/O code.
 */
int kh_pin(const char *store_path, const char *instance_id,
           const char *scanned_key_line);

/* True iff the store contains a pinned entry for `instance_id`. */
bool kh_bound(const char *store_path, const char *instance_id);

/*
 * Remove every entry for `instance_id` from the store. Idempotent: a missing
 * store or entry is success. Returns 0 or an errno-style code.
 */
int kh_forget(const char *store_path, const char *instance_id);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_KNOWNHOSTS_H */
