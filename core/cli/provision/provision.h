/*
 * provision.h — `stackctl provision` (spec §4 provision).
 *
 * Deploys the account-global `<project>-operator` CloudFormation stack from
 * the primary config and verifies the project identity. The verb body lives in
 * provision_run(); this header exposes only the frozen entry point.
 */

#ifndef STACKCTL_CLI_PROVISION_PROVISION_H
#define STACKCTL_CLI_PROVISION_PROVISION_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_provision(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_PROVISION_PROVISION_H */
