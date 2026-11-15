/*
 * launch.h — public entry point for `stackctl launch` (spec §4).
 *
 * The wave-5 dispatcher only needs cli_cmd_launch; orchestration lives in
 * launch_internal.h.
 */

#ifndef STACKCTL_CLI_LAUNCH_LAUNCH_H
#define STACKCTL_CLI_LAUNCH_LAUNCH_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_launch(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_LAUNCH_LAUNCH_H */
