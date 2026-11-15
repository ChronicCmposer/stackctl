/*
 * startstop.h — public entry points for `stackctl start` and `stackctl stop`
 * (spec §4). Both SSH-exec `systemctl start|stop <SERVICE_UNIT>` on the
 * Project-tagged instance and hold the project lock.
 */

#ifndef STACKCTL_CLI_STARTSTOP_STARTSTOP_H
#define STACKCTL_CLI_STARTSTOP_STARTSTOP_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_start(cli_ctx *ctx);
int cli_cmd_stop(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_STARTSTOP_STARTSTOP_H */
