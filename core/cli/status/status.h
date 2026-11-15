/*
 * status.h — public entry point for `stackctl status` (spec §4).
 *
 * Read-only and lockless: the wave-5 dispatcher only needs cli_cmd_status.
 * Orchestration lives in status_internal.h.
 */

#ifndef STACKCTL_CLI_STATUS_STATUS_H
#define STACKCTL_CLI_STATUS_STATUS_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_status(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_STATUS_STATUS_H */
