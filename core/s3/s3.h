/*
 * s3.h — S3 request builders and response parsers over core/aws (spec §5.5).
 *
 * Path-style addressing only (`/<bucket>/<key>`), `UNSIGNED-PAYLOAD` for
 * PUT/GET/HEAD, no multipart uploads (single PUTs per spec §5.5). The module
 * never opens a socket: every request goes through the core/aws seam.
 *
 * Error model (CONTRACT.md): functions return 0 on success, else a non-zero
 * errno-style code. HTTP error responses are mapped from their S3 XML error
 * code (NoSuchKey/NoSuchBucket -> ENOENT, AccessDenied -> EACCES,
 * BucketAlreadyOwnedByYou -> EEXIST, ...). Diagnostics go to stderr only.
 */

#ifndef STACKCTL_CORE_S3_S3_H
#define STACKCTL_CORE_S3_S3_H

#include <stddef.h>

#include "../aws/aws.h"

#ifdef __cplusplus
extern "C" {
#endif

#define S3_ETAG_MAX 128
#define S3_SHA256_HEX_LEN 65
#define S3_DATE_MAX 64

/* Opaque client: an initialized aws_ctx plus the request region. */
typedef struct s3_client s3_client;

/* One object entry from ListObjectsV2. `key` is heap-owned by its list. */
typedef struct s3_object_info {
    char *key;
    char etag[S3_ETAG_MAX]; /* surrounding quotes stripped */
    unsigned long long size;
    char last_modified[S3_DATE_MAX];
} s3_object_info;

/* Result of ListObjectsV2 (single page). Release with s3_object_list_free(). */
typedef struct s3_object_list {
    s3_object_info *items;
    size_t count;
    int truncated;
    char *next_token; /* heap-owned continuation token, or NULL */
} s3_object_list;

/* The four S3 Block Public Access settings (spec §6.2: all true). */
typedef struct s3_public_access_block {
    int block_public_acls;
    int ignore_public_acls;
    int block_public_policy;
    int restrict_public_buckets;
} s3_public_access_block;

/*
 * Create a client bound to an aws_ctx and the request region. The client does
 * not own the aws_ctx. Returns 0, else EINVAL/ENOMEM.
 */
int s3_client_init(s3_client **out, aws_ctx *aws, const char *region);

/* Release a client from s3_client_init(). Safe on NULL. */
void s3_client_free(s3_client *client);

/* --- objects ----------------------------------------------------------- */

/*
 * PUT one object in a single request (no multipart, spec §5.5). `data` may be
 * NULL only when `len` is 0; `content_type` may be NULL. On success the ETag
 * response header (quotes stripped) is copied to `etag_out` when non-NULL.
 */
int s3_put_object(s3_client *client, const char *bucket, const char *key,
                  const void *data, size_t len, const char *content_type,
                  char etag_out[S3_ETAG_MAX]);

/*
 * GET one object. On success `*data_out` receives a heap buffer of `*len_out`
 * bytes (NUL-terminated for convenience, not counted in `*len_out`); release
 * with free(). Out-params are untouched on failure.
 */
int s3_get_object(s3_client *client, const char *bucket, const char *key,
                  char **data_out, size_t *len_out);

/*
 * HEAD one object: report Content-Length and ETag without downloading it.
 * Missing object/bucket maps to ENOENT.
 */
int s3_head_object(s3_client *client, const char *bucket, const char *key,
                   unsigned long long *size_out, char etag_out[S3_ETAG_MAX]);

/* DELETE one object. Deleting an absent object is a success (S3 semantics). */
int s3_delete_object(s3_client *client, const char *bucket, const char *key);

/*
 * ListObjectsV2 (single page, `list-type=2`). `prefix` may be NULL/empty.
 * On success `out` is populated and must be released with
 * s3_object_list_free(). Errors leave `out` zeroed.
 */
int s3_list_objects_v2(s3_client *client, const char *bucket, const char *prefix,
                       s3_object_list *out);

/* Release a list populated by s3_list_objects_v2(). Safe on NULL/zeroed. */
void s3_object_list_free(s3_object_list *list);

/* --- read-back sha256 helpers (over core/crypto) ------------------------ */

/* Lowercase hex SHA-256 of `len` bytes at `data` into `out`. Returns 0. */
int s3_sha256_hex(const void *data, size_t len, char out[S3_SHA256_HEX_LEN]);

/*
 * Compare the SHA-256 of `len` bytes at `data` with an expected lowercase hex
 * digest. Returns 0 on match, EBADMSG on mismatch, EINVAL on bad arguments.
 */
int s3_sha256_verify(const void *data, size_t len, const char *expected_hex);

/*
 * GET an object and verify its read-back sha256 before handing it to the
 * caller. On mismatch `*data_out`/`*len_out` are untouched (EBADMSG).
 */
int s3_get_object_sha256(s3_client *client, const char *bucket, const char *key,
                         const char *expected_hex, char **data_out,
                         size_t *len_out);

/* --- buckets ----------------------------------------------------------- */

/*
 * Create a bucket in the client's region. For any region other than
 * us-east-1 the CreateBucketConfiguration LocationConstraint body is sent.
 * A bucket already owned by the caller maps to EEXIST.
 */
int s3_create_bucket(s3_client *client, const char *bucket);

/* Delete an empty bucket. A missing bucket maps to ENOENT. */
int s3_delete_bucket(s3_client *client, const char *bucket);

/* HEAD a bucket (existence check). A missing bucket maps to ENOENT. */
int s3_head_bucket(s3_client *client, const char *bucket);

/*
 * GET the bucket location constraint. us-east-1 reports an empty
 * LocationConstraint, which this function normalizes to "us-east-1".
 */
int s3_get_bucket_location(s3_client *client, const char *bucket,
                           char *region_out, size_t region_cap);

/* --- bucket configuration subresources -------------------------------- */

/* PUT ?versioning; enabled != 0 -> Enabled, else Suspended. */
int s3_set_versioning(s3_client *client, const char *bucket, int enabled);

/* GET ?versioning. Suspended yields *enabled == 0. */
int s3_get_versioning(s3_client *client, const char *bucket, int *enabled);

/* PUT ?publicAccessBlock with all four flags. */
int s3_set_public_access_block(s3_client *client, const char *bucket,
                               const s3_public_access_block *block);

/* GET ?publicAccessBlock. A bucket without a configuration maps to ENOENT. */
int s3_get_public_access_block(s3_client *client, const char *bucket,
                               s3_public_access_block *out);

/*
 * PUT ?encryption with one default rule. `algorithm` is "AES256" (SSE-S3) or
 * "aws:kms"; `kms_key_id` may be NULL except for aws:kms.
 */
int s3_set_encryption(s3_client *client, const char *bucket,
                      const char *algorithm, const char *kms_key_id);

/* GET ?encryption; reports the default SSEAlgorithm. Missing config ENOENT. */
int s3_get_encryption(s3_client *client, const char *bucket,
                      char *algorithm_out, size_t algorithm_cap);

/* PUT ?lifecycle with a caller-supplied LifecycleConfiguration XML document. */
int s3_put_lifecycle(s3_client *client, const char *bucket, const char *xml);

/* GET ?lifecycle; returns the raw XML document (heap, free with free()). */
int s3_get_lifecycle(s3_client *client, const char *bucket, char **xml_out);

/* DELETE ?lifecycle. */
int s3_delete_lifecycle(s3_client *client, const char *bucket);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_S3_S3_H */
