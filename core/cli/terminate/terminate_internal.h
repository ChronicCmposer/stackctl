/*
 * terminate_internal.h — orchestration seam for `stackctl terminate`.
 *
 * `terminate_execute` is the whole verb body against an injected runtime; it is
 * what the unit tests drive. `cli_cmd_terminate` in terminate.c is the thin
 * production wrapper (parse argv, open services, call execute).
 */

#ifndef STACKCTL_CLI_TERMINATE_INTERNAL_H
#define STACKCTL_CLI_TERMINATE_INTERNAL_H

#include "core/cli/launch/common/instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct terminate_options {
    const char *instance_id; /* --instance-id, or NULL for the full sweep */
} terminate_options;

/* Frozen option table (exposed for argv tests). */
extern const cli_option_spec terminate_option_specs[];
extern const size_t terminate_option_count;

/*
 * Run terminate. Returns a frozen CLI_EXIT_* code:
 *   0 success (including the zero-instance no-op sweep and a clean park),
 *   1 usage (--instance-id not found or not Project-tagged, bad args),
 *   2 AWS API error,
 *   5 teardown incomplete (terminate waiter timeout, DDNS park failure).
 */
int terminate_execute(instance_runtime *rt, const terminate_options *opts);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_TERMINATE_INTERNAL_H */
