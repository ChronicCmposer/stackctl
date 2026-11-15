/*
 * terminate.h — public entry point for `stackctl terminate` (spec §4).
 *
 * Stays intentionally minimal: the wave-5 dispatcher only needs the frozen
 * `cli_cmd_terminate` prototype from core/cli/cli.h. The orchestration seam
 * lives in terminate_internal.h.
 */

#ifndef STACKCTL_CLI_TERMINATE_TERMINATE_H
#define STACKCTL_CLI_TERMINATE_TERMINATE_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_terminate(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_TERMINATE_TERMINATE_H */
