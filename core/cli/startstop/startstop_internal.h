/*
 * startstop_internal.h — orchestration seam shared by `stackctl start` and
 * `stackctl stop`. Both act on the systemd unit over SSH and hold the project
 * lock (acquired by cli_ctx_init).
 */

#ifndef STACKCTL_CLI_STARTSTOP_INTERNAL_H
#define STACKCTL_CLI_STARTSTOP_INTERNAL_H

#include "core/cli/launch/common/instance.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum startstop_action {
    STARTSTOP_START = 1,
    STARTSTOP_STOP = 2
} startstop_action;

typedef struct startstop_options {
    const char *instance_id;   /* --instance-id, or NULL */
    int trust_new_host_key;    /* --trust-new-host-key (TOFU only here) */
} startstop_options;

extern const cli_option_spec startstop_option_specs[];
extern const size_t startstop_option_count;

/*
 * Run start/stop. Exit codes (spec §4):
 *   0 success; 1 usage (missing SERVICE_UNIT, zero/ambiguous target, untagged
 *   --instance-id, remote systemctl non-zero); 2 AWS API error; 3 host-key
 *   mismatch; 7 SSH transport failure or unverifiable host key.
 */
int startstop_execute(instance_runtime *rt, const startstop_options *opts,
                      startstop_action action);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_STARTSTOP_INTERNAL_H */
