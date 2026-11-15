/*
 * refresh_ami.h — `stackctl refresh-ami` (spec §4 refresh-ami).
 *
 * Resolves the current SSM float for every declared arch and dual-writes the
 * pins into the local `.env` and its committed `.env.example` counterpart.
 */

#ifndef STACKCTL_CLI_REFRESH_AMI_REFRESH_AMI_H
#define STACKCTL_CLI_REFRESH_AMI_REFRESH_AMI_H

#include "cli.h"

#ifdef __cplusplus
extern "C" {
#endif

int cli_cmd_refresh_ami(cli_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_REFRESH_AMI_REFRESH_AMI_H */
