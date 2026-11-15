/*
 * deploy_internal.h — injectable seams for the deploy verb.
 *
 * Deploy is a release-publish + CloudFormation-update pipeline. Each stage is a
 * vtable entry (git provenance, freshness, S3 release publish/verify, AMI
 * preflight, CFN change set, confirmation) so unit tests can assert order,
 * idempotency and failure semantics without git, bazel, credentials or network.
 *
 * Optional stages return a frozen cli_exit_code directly (0 on success) where
 * the failure class is part of the spec: provenance -> 1/3, freshness -> 6,
 * release verification -> 3, AWS-bound operations -> 2.
 */

#ifndef STACKCTL_CLI_DEPLOY_INTERNAL_H
#define STACKCTL_CLI_DEPLOY_INTERNAL_H

#include <stddef.h>
#include <stdio.h>

#include "cfn.h"
#include "cli.h"
#include "deploy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct deploy_ops {
    /* Provenance: fills `tag` on success; returns 0, CLI_EXIT_USAGE (ambiguous)
     * or CLI_EXIT_VERIFY (missing/remote/annotated/dirty). */
    int (*git_provenance)(void *ud, const char *repo_root, int allow_dirty,
                          char *tag, size_t cap);
    /* Freshness: returns 0 or CLI_EXIT_FRESHNESS. */
    int (*freshness)(void *ud, const char *repo_root, const char *targets);
    /* Account-derived artifact bucket name. */
    int (*resolve_bucket)(void *ud, const char *project, const char *region,
                          char *out, size_t cap);
    /* Effective AMI for one arch (pinned/ssm/baked per AMI_POLICY). */
    int (*resolve_ami)(void *ud, const stackctl_config *cfg, const char *region,
                       const char *arch, char *out, size_t cap);
    /* Does the AMI resolve in the region? */
    int (*ami_exists)(void *ud, const char *region, const char *ami, int *found);
    /* Complete, verified manifest present under releases/<tag>/? */
    int (*release_exists)(void *ud, const char *bucket, const char *tag,
                          int *exists);
    /* Verify the existing release by read-back; fills its manifest sha256. */
    int (*verify_release)(void *ud, const char *bucket, const char *tag,
                          char *sha_out, size_t cap);
    /* Publish a new release (sidecars, objects, manifest) and verify; fills the
     * manifest sha256. */
    int (*publish_release)(void *ud, const char *bucket, const char *tag,
                           const char *repo_root, const char *targets,
                           char *sha_out, size_t cap);

    /* Count running/pending Project-tagged instances (best effort preview). */
    int (*count_live_instances)(void *ud, const char *region, int *count);
    /* Prune old releases (spec §7.4). Protections always win. */
    int (*prune_releases)(void *ud, const char *bucket, const char *pinned_tag,
                          const char *previous_tag, const char *just_uploaded);

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
                           int attempts, int interval_sec, int *timed_out);
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
    /* Optional: read the canonical template body from the checkout. NULL => "". */
    int (*read_template)(void *ud, const char *repo_root, char **body_out);
    /* Optional: read a fully resolved template path (canonical or override).
     * When set, deploy runs the §6.3 structural checker before any AWS call. */
    int (*read_template_path)(void *ud, const char *path, char **body_out);
} deploy_ops;

typedef struct deploy_env {
    const stackctl_config *cfg;
    const char *config_dir;
    const char *tag_arg; /* --tag <vX.Y.Z> rollback, or NULL */
    int allow_dirty;
    int skip_build;
    int yes;
    int dry_run;
    int json;
    FILE *out;
    FILE *err;

    char tag[128];          /* resolved release tag */
    char previous_tag[128]; /* tag recorded immediately before this one */
    char manifest_sha[65];  /* verified/published manifest sha256 */
    int executed;           /* stack update executed */

    const deploy_ops *ops;
    void *ops_ud;
    int (*confirm)(void *ud, const char *prompt);
    void *confirm_ud;
} deploy_env;

/* One release prefix considered by the prune selector (spec §7.4). */
typedef struct deploy_release_entry {
    char tag[128];
    long long manifest_epoch; /* manifest LastModified; 0 = no manifest */
    long long newest_epoch;   /* newest object LastModified in the prefix */
    int delete_me;            /* set by deploy_prune_mark() */
} deploy_release_entry;

/*
 * Parse an S3 ISO-8601 timestamp (`2024-01-02T15:04:05.000Z`) to epoch seconds.
 * Returns 0 on success, EINVAL on a malformed value.
 */
int deploy_iso8601_to_epoch(const char *iso, long long *out);

/*
 * Mark which release entries the prune stage deletes. Keeps the 10 newest
 * manifest-bearing releases (by manifest LastModified), never deletes a
 * protected tag (pinned/previous/just-uploaded), and deletes manifest-less
 * garbage prefixes older than 24 h. Unverifiable entries are kept. Returns the
 * number of marked entries.
 */
size_t deploy_prune_mark(deploy_release_entry *entries, size_t count,
                         const char *pinned, const char *previous,
                         const char *just_uploaded, long long now_epoch);

/* Format one manifest line: `<sha256>  <member>\n` (sha first, two spaces). */
int deploy_manifest_line(const char *sha, const char *member, char *out,
                         size_t cap);

/*
 * Write a human-readable per-parameter diff between the current stack's
 * parameters (`current`, or NULL for a brand-new stack) and the planned
 * `params`. Each changed parameter is rendered as
 *   <name>: Added = <new>
 *   <name>: Changed: <old> -> <new>
 *   <name>: Removed = <old>
 * prefixed by a `parameter changes:` header. Prints nothing and returns 0 when
 * there are no differences.
 */
size_t deploy_param_diff_write(FILE *out, const cfn_stack *current,
                               const cfn_parameter *params,
                               size_t param_count);

/* Single-quote `in` for POSIX sh, escaping embedded single quotes. */
int deploy_shell_quote(const char *in, char *out, size_t cap);

/* Run the verb body; returns a frozen cli_exit_code value. */
int deploy_run(deploy_env *env);

/* Test-only override consumed by cli_cmd_deploy(). */
void deploy_set_ops_for_test(const deploy_ops *ops, void *ud);

/* Test-only: the production aws_init seam, so tests can assert the signal
 * abort hook is installed on a real client. */
int deploy_prod_aws_init_for_test(const char *profile, aws_ctx **out);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CLI_DEPLOY_INTERNAL_H */
