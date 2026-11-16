/*
 * provision_internal.h — injectable seams for the provision verb.
 *
 * Provision is an orchestration over CloudFormation with a small amount of
 * local credential/identity work. Every AWS-bound step is a vtable entry so
 * unit tests can drive the exact order of operations without credentials or a
 * network. The template body and the identity/keys step are seams too.
 */

#ifndef STACKCTL_CLI_PROVISION_INTERNAL_H
#define STACKCTL_CLI_PROVISION_INTERNAL_H

#include <stddef.h>
#include <stdio.h>

#include "cfn.h"
#include "cli.h"
#include "iam.h"
#include "provision.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct provision_ops {
    int (*aws_init)(void *ud, const char *profile, aws_ctx **out);
    void (*aws_free)(void *ud, aws_ctx *aws);
    int (*cfn_create)(void *ud, aws_ctx *aws, cfn_client **out);
    void (*cfn_destroy)(void *ud, cfn_client *client);
    int (*describe_stacks)(void *ud, cfn_client *client, const char *region,
                           const char *stack_name, cfn_stack_list *out);
    void (*stack_list_free)(void *ud, cfn_stack_list *list);
    int (*create_change_set)(void *ud, cfn_client *client, const char *region,
                             const cfn_change_set_spec *spec,
                             cfn_change_set_result *out);
    int (*wait_change_set)(void *ud, cfn_client *client, const char *region,
                           const char *stack_name, const char *change_set_name,
                           int attempts, int interval_sec, int *timed_out,
                           int *no_changes);
    int (*describe_change_set)(void *ud, cfn_client *client, const char *region,
                               const char *stack_name,
                               const char *change_set_name,
                               cfn_change_set *out);
    void (*change_set_free)(void *ud, cfn_change_set *change_set);
    int (*execute_change_set)(void *ud, cfn_client *client, const char *region,
                              const char *stack_name,
                              const char *change_set_name);
    int (*delete_change_set)(void *ud, cfn_client *client, const char *region,
                             const char *stack_name,
                             const char *change_set_name);
    int (*wait_stack)(void *ud, cfn_client *client, const char *region,
                      const char *stack_name, cfn_wait_operation operation,
                      int attempts, int interval_sec, int *timed_out);
    int (*delete_stack)(void *ud, cfn_client *client, const char *region,
                        const char *stack_name);
    /* IAM/STS identity + access-key management (CONTRACT Amendment 6). */
    int (*iam_identity)(void *ud, aws_ctx *ctx, char **out_arn);
    int (*iam_list_keys)(void *ud, aws_ctx *ctx, const char *user,
                         iam_key **out, size_t *out_count);
    int (*iam_create_key)(void *ud, aws_ctx *ctx, const char *user,
                          iam_key *out);
    int (*iam_delete_key)(void *ud, aws_ctx *ctx, const char *user,
                          const char *key_id);
    void (*iam_key_free)(void *ud, iam_key *key);
    void (*iam_keys_free)(void *ud, iam_key *keys, size_t count);
    /* Local ~/.aws/credentials helpers (ini-backed writes with backup). */
    int (*credentials_key_id)(void *ud, const char *profile, char **out);
    int (*credentials_write)(void *ud, const char *profile, const char *key_id,
                             const char *secret, char **backup_out);
    /* Retry back-off hook; tests make this a no-op. */
    void (*retry_pause)(void *ud);
    int (*read_template)(void *ud, const char *repo_root, char **body_out);
    /*
     * Path-labelled template read. When set, provision loads the canonical
     * operator template through this seam and names it in §6.3 diagnostics.
     */
    int (*read_template_path)(void *ud, const char *path, char **body_out);
} provision_ops;

typedef struct provision_env {
    const stackctl_config *cfg;
    const char *config_dir;
    int region_variant; /* non-zero when --region loaded a variant */
    int yes;
    int dry_run;
    int json;
    int rotate;
    int rotate_ci;
    FILE *out;
    FILE *err;

    const provision_ops *ops;
    void *ops_ud;
    int (*confirm)(void *ud, const char *prompt);
    void *confirm_ud;
} provision_env;

/* Run the verb body; returns a frozen cli_exit_code value. */
int provision_run(const provision_env *env);

/*
 * True when the loaded config is a non-primary region variant (i.e. it was
 * selected by --region). Derived from the config's REGION versus the primary
 * `.env`'s REGION, never from `.env.<region>` file existence.
 */
int provision_region_variant(const char *config_dir,
                             const stackctl_config *cfg);

/*
 * Ensure the operator (and CI) IAM users each have exactly one usable access
 * key and that the local profiles are written. `admin_aws` is the [default]
 * admin context used for IAM management. Sets *identity_mismatch when the
 * project caller ARN is not :user/<project>. Returns 0 or an errno-style code.
 */
int provision_ensure_keys(const provision_env *env, const provision_ops *ops,
                          void *ud, aws_ctx *admin_aws,
                          int *identity_mismatch);

/* Test-only override consumed by cli_cmd_provision(). */
void provision_set_ops_for_test(const provision_ops *ops, void *ud);

/* Test-only: the production aws_init seam, so tests can assert the signal
 * abort hook is installed on a real client. */
int provision_prod_aws_init_for_test(const char *profile, aws_ctx **out);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_PROVISION_INTERNAL_H */
