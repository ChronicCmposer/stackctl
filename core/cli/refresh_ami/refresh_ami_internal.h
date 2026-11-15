/*
 * refresh_ami_internal.h — injectable seams for the refresh-ami verb.
 *
 * The public entry point is `cli_cmd_refresh_ami` (see refresh_ami.h). The verb
 * body lives in refresh_ami_run() so unit tests can inject:
 *
 *   - a parameter resolver (production: core/aws + core/ssm; tests: a fake),
 *   - the config directory and output streams,
 *   - the file reader/writer (production: realpath + same-directory rename;
 *     tests may use the real implementation against temp files).
 *
 * `refresh_ami_set_ops_for_test` is a test-only override consumed by the public
 * entry point; production leaves it NULL and uses the real resolver.
 */

#ifndef STACKCTL_CLI_REFRESH_AMI_INTERNAL_H
#define STACKCTL_CLI_REFRESH_AMI_INTERNAL_H

#include <stddef.h>
#include <stdio.h>

#include "aws.h"
#include "cli.h"
#include "refresh_ami.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve one SSM parameter name to its plaintext value (heap-owned). */
typedef struct refresh_ami_ops {
    int (*resolve_parameter)(void *ud, const char *profile, const char *region,
                             const char *name, char **value_out);
} refresh_ami_ops;

/* File seam; a NULL field selects the production implementation. */
typedef struct refresh_ami_file_ops {
    int (*read_file)(void *ud, const char *path, char **data_out,
                     size_t *len_out);
    int (*write_atomic)(void *ud, const char *path, const char *data,
                        size_t len);
} refresh_ami_file_ops;

typedef struct refresh_ami_env {
    const stackctl_config *cfg;
    const char *profile;     /* AWS profile (project identity) */
    const char *config_dir;  /* project config directory */
    const char *region;      /* config region */
    int dry_run;
    int json;
    FILE *out;
    FILE *err;

    const refresh_ami_ops *ops;
    void *ops_ud;
    const refresh_ami_file_ops *file_ops; /* optional */
    void *file_ud;
} refresh_ami_env;

/* Run the verb body; returns a frozen cli_exit_code value. */
int refresh_ami_run(const refresh_ami_env *env);

/* Test-only seam: override the resolver used by cli_cmd_refresh_ami(). */
void refresh_ami_set_ops_for_test(const refresh_ami_ops *ops, void *ud);

/* Test-only: the production aws_init seam, so tests can assert the signal
 * abort hook is installed on a real client. */
int refresh_ami_prod_aws_init_for_test(const char *profile, aws_ctx **out);

/* Test-only seam: override file operations. */
void refresh_ami_set_file_ops_for_test(const refresh_ami_file_ops *ops,
                                       void *ud);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_REFRESH_AMI_INTERNAL_H */
