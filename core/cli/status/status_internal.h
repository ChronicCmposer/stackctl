/*
 * status_internal.h — orchestration seam for `stackctl status`.
 *
 * status_execute is read-only and lockless; it reports preflight state, the
 * infra stack, Project-tagged instances and their AMIs, DDNS, release identity,
 * known-hosts bindings and warnings. Exit codes follow spec §4: 0 (possibly with
 * warnings), 1 preflight failure, 2 AWS error, 3 identity guard.
 */

#ifndef STACKCTL_CLI_STATUS_INTERNAL_H
#define STACKCTL_CLI_STATUS_INTERNAL_H

#include "core/cli/launch/common/instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct status_options {
    int reserved; /* no verb-specific options in v1 */
    /*
     * Preflight inputs supplied by the dispatcher-facing entry point. Tests may
     * leave them NULL to skip the corresponding filesystem probe; production
     * always sets both.
     *
     *   config_dir    resolved --project directory (repo-root discovery)
     *   bazel_command configured BAZEL_COMMAND (existence check, never run)
     */
    const char *config_dir;
    const char *bazel_command;
} status_options;

int status_execute(instance_runtime *rt, const status_options *opts);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_STATUS_INTERNAL_H */
