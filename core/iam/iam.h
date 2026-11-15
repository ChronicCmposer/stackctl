/*
 * iam.h — AWS IAM + STS Query-protocol client (CONTRACT Amendment 6).
 *
 * Request-builders and response-parsers over the frozen core/aws seam only.
 * Every operation issues one form-encoded `POST /` Query request
 * (`Action=...&Version=...`) and parses the XML response:
 *
 *   - STS `GetCallerIdentity`  (Version=2011-06-15, service "sts")
 *   - IAM `ListAccessKeys`     (Version=2010-05-08, service "iam")
 *   - IAM `CreateAccessKey`    (Version=2010-05-08, service "iam")
 *   - IAM `DeleteAccessKey`    (Version=2010-05-08, service "iam")
 *
 * IAM and STS are global services; requests are signed for `us-east-1`, the
 * SigV4 region of their global endpoints.
 *
 * Error model: functions return 0 on success and a positive errno-style code
 * otherwise; out-params are untouched on failure. AWS error documents are
 * reported on stderr as `<Code>: <Message>` (never including secrets) and
 * translated: NoSuchEntity -> ENOENT, AccessDenied / InvalidClientTokenId /
 * SignatureDoesNotMatch -> EACCES, any other API error -> IAM_ERR_AWS_API.
 *
 * `user_name_or_null == NULL` addresses the caller's own IAM user.
 */

#ifndef STACKCTL_CORE_IAM_IAM_H
#define STACKCTL_CORE_IAM_IAM_H

#include <stddef.h>

#include "core/aws/aws.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returned when AWS answered with an error document. Matches EREMOTEIO like
 * the other service modules so the CLI maps it to its AWS-API exit code. */
#define IAM_ERR_AWS_API 121

/*
 * One IAM access-key record. All fields are heap-owned; release the whole
 * struct with iam_key_free().
 *
 * `secret_access_key` is non-NULL only in an iam_create_access_key() result.
 * `status` is "Active" or "Inactive". `create_date` is the ISO-8601 string as
 * returned by AWS (may be NULL when absent).
 */
typedef struct iam_key {
    char *user_name;
    char *access_key_id;
    char *secret_access_key; /* NULL except for iam_create_access_key results */
    char *status;            /* "Active"/"Inactive" */
    char *create_date;       /* ISO-8601 as returned */
} iam_key;

/*
 * STS GetCallerIdentity. On success each non-NULL out-param receives a
 * heap-allocated NUL-terminated string owned by the caller (free(3)). Any
 * out-param may be NULL when the caller does not need it. Out-params are
 * untouched on failure.
 */
int iam_get_caller_identity(aws_ctx *ctx, char **out_account, char **out_arn,
                            char **out_user_id);

/*
 * IAM ListAccessKeys for `user_name_or_null` (NULL = the caller's own user).
 * Follows `Marker`/`IsTruncated` pagination and returns every key in a
 * heap-owned array (release with iam_keys_free()). On success `*out` is NULL
 * and `*out_count` is 0 when the user has no keys. `*out`/`*out_count` are
 * untouched on failure.
 */
int iam_list_access_keys(aws_ctx *ctx, const char *user_name_or_null,
                         iam_key **out, size_t *out_count);

/*
 * IAM CreateAccessKey for `user_name_or_null` (NULL = the caller's own user).
 * `*out` must be zero-initialised by the caller; on success it receives the
 * new key including its `secret_access_key`. `*out` is untouched on failure.
 * The secret is never written to stderr or any log.
 */
int iam_create_access_key(aws_ctx *ctx, const char *user_name_or_null,
                          iam_key *out);

/*
 * IAM DeleteAccessKey for `user_name_or_null` (NULL = the caller's own user).
 * Deleting an absent key maps NoSuchEntity to ENOENT.
 */
int iam_delete_access_key(aws_ctx *ctx, const char *user_name_or_null,
                          const char *access_key_id);

/* Release every heap field of `key` and zero the struct. Safe on NULL. */
void iam_key_free(iam_key *key);

/* Release every key in `keys` (each via iam_key_free) and the array. Safe on
 * NULL or count 0. */
void iam_keys_free(iam_key *keys, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_IAM_IAM_H */
