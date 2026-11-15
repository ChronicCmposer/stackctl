/*
 * cli_identity.c — shared project-identity guard for mutating verbs (C1/F3).
 *
 * Mirrors the five existing per-verb guards: the caller ARN must end in
 * `:user/<project>`. Assumed-role ARNs are rejected explicitly so the operator
 * gets a message that names the problem instead of a bare suffix mismatch.
 * Account-id verification is deferred (no configured account key).
 */

#include "cli.h"

#include "iam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* An STS assumed-role ARN (`arn:aws:sts::<acct>:assumed-role/...`). */
static int arn_is_assumed_role(const char *arn) {
    return strstr(arn, ":assumed-role/") != NULL;
}

int cli_assert_operator_identity(struct aws_ctx *aws, const char *project) {
    char *arn = NULL;
    char suffix[300];
    size_t arn_len;
    size_t suffix_len;
    int rc;

    if (aws == NULL || project == NULL || project[0] == '\0') {
        fprintf(stderr,
                "stackctl: identity guard: missing AWS client or project\n");
        return CLI_EXIT_USAGE;
    }

    rc = iam_get_caller_identity(aws, NULL, &arn, NULL);
    if (rc != 0) {
        free(arn);
        fprintf(stderr, "stackctl: cannot verify the caller identity\n");
        return CLI_EXIT_AWS;
    }
    if (arn == NULL) {
        fprintf(stderr, "stackctl: identity guard: no caller ARN returned\n");
        return CLI_EXIT_VERIFY;
    }

    if (arn_is_assumed_role(arn)) {
        fprintf(stderr,
                "stackctl: identity guard: caller is an assumed role (%s); "
                "stackctl requires the project IAM user arn:...:user/%s\n",
                arn, project);
        free(arn);
        return CLI_EXIT_VERIFY;
    }

    snprintf(suffix, sizeof suffix, ":user/%s", project);
    arn_len = strlen(arn);
    suffix_len = strlen(suffix);
    if (arn_len < suffix_len ||
        strcmp(arn + (arn_len - suffix_len), suffix) != 0) {
        fprintf(stderr,
                "stackctl: identity guard: %s does not end with %s (expected "
                "the project IAM user)\n",
                arn, suffix);
        free(arn);
        return CLI_EXIT_VERIFY;
    }

    free(arn);
    return CLI_EXIT_OK;
}
