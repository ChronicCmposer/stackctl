/*
 * launch_internal.h — orchestration seam for `stackctl launch` (spec §4).
 */

#ifndef STACKCTL_CLI_LAUNCH_INTERNAL_H
#define STACKCTL_CLI_LAUNCH_INTERNAL_H

#include "core/cli/launch/common/instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct launch_options {
    const char *arch;
    const char *instance_type;
    const char *variant;
    int spot_set;          /* -1 = config default, 0 = no-spot, 1 = spot */
    int keep_on_failure;
    int keep_old;
    int instance_timeout;  /* seconds; 0 => default 300 */
    int ssh_timeout;       /* seconds; 0 => default 300 */
    int setup_timeout;     /* seconds; 0 => default 1800 */
} launch_options;

extern const cli_option_spec launch_option_specs[];
extern const size_t launch_option_count;

/*
 * Run launch. Exit codes (spec §4):
 *   0 success; 1 usage/preflight; 2 AWS API error; 3 verification failure;
 *   4 launch failed and the instance was terminated; 5 cleanup incomplete;
 *   7 SSH transport failure.
 */
int launch_execute(instance_runtime *rt, const launch_options *opts);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_LAUNCH_INTERNAL_H */
