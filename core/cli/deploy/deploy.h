/*
 * deploy.h — `stackctl deploy` (spec §4 deploy).
 */

#ifndef STACKCTL_CLI_DEPLOY_DEPLOY_H
#define STACKCTL_CLI_DEPLOY_DEPLOY_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_deploy(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_DEPLOY_DEPLOY_H */
