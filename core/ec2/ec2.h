/*
 * ec2.h — AWS EC2 Query-protocol client (spec §4 launch/terminate/status,
 * CONTRACT.md §core/ec2/ec2.h).
 *
 * Request-builders and response-parsers over core/aws only. Every operation
 * issues one EC2 Query request (`POST /` with a form-encoded `Action` body) and
 * parses the XML response. All public symbols are prefixed `ec2_`.
 *
 * Error model (CONTRACT.md): these functions return 0 on success and a
 * non-zero errno-style code otherwise; out-params are untouched on failure.
 * `EC2_ERR_AWS_API` (EREMOTEIO) is returned when AWS answered with an error
 * document; an operator-facing diagnostic including the AWS error code and
 * message is written to stderr (capacity rejections and UnauthorizedOperation
 * carry the hints from spec §4). Diagnostics go to stderr only.
 *
 * No global mutable state: the client owns the connection context, region and
 * the transport seam. Tests inject a fake transport through ec2_internal.h.
 */

#ifndef STACKCTL_CORE_EC2_EC2_H
#define STACKCTL_CORE_EC2_EC2_H

#include <stddef.h>

#include "core/aws/aws.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Field capacities for parsed EC2 resources. */
#define EC2_INSTANCE_ID_MAX 64
#define EC2_STATE_NAME_MAX 32
#define EC2_IP_MAX 64
#define EC2_TYPE_MAX 64
#define EC2_IMAGE_ID_MAX 64
#define EC2_TAG_KEY_MAX 128
#define EC2_TAG_VALUE_MAX 256
#define EC2_MAX_TAGS 24
#define EC2_IMAGE_NAME_MAX 256
#define EC2_ARCH_MAX 32
#define EC2_ERROR_CODE_MAX 128

/*
 * Returned when AWS answered with an error document (HTTP non-2xx or an XML
 * `<Errors><Error>` envelope). Never an errno value defined by the platform;
 * the CLI maps it to its AWS-API exit code.
 */
#define EC2_ERR_AWS_API 121 /* EREMOTEIO */

/* One resource tag. */
typedef struct ec2_tag {
    char key[EC2_TAG_KEY_MAX];
    char value[EC2_TAG_VALUE_MAX];
} ec2_tag;

/* One instance as returned by DescribeInstances/RunInstances. */
typedef struct ec2_instance {
    char instance_id[EC2_INSTANCE_ID_MAX];
    char state[EC2_STATE_NAME_MAX]; /* pending|running|stopping|stopped|shutting-down|terminated */
    char image_id[EC2_IMAGE_ID_MAX];
    char instance_type[EC2_TYPE_MAX];
    char public_ip[EC2_IP_MAX];  /* empty until assigned */
    char private_ip[EC2_IP_MAX]; /* empty until assigned */
    ec2_tag tags[EC2_MAX_TAGS];
    size_t tag_count;
} ec2_instance;

typedef struct ec2_instance_list {
    ec2_instance *items;
    size_t count;
} ec2_instance_list;

/* One DescribeInstances filter (`Filter.N.Name` + repeated values). */
typedef struct ec2_filter {
    const char *name;
    const char *const *values;
    size_t value_count;
} ec2_filter;

/* One image returned by DescribeImages (preflight and root-device lookup). */
typedef struct ec2_image {
    char image_id[EC2_IMAGE_ID_MAX];
    char state[EC2_STATE_NAME_MAX];
    char name[EC2_IMAGE_NAME_MAX];
    char architecture[EC2_ARCH_MAX];
    char root_device_name[EC2_TYPE_MAX];
} ec2_image;

typedef struct ec2_image_list {
    ec2_image *items;
    size_t count;
} ec2_image_list;

/* RunInstances inputs. Every pointer is borrowed for the call. */
typedef struct ec2_run_spec {
    const char *ami_id;                /* required; the effective AMI */
    const char *instance_type;         /* required; validated by the caller */
    const char *key_name;              /* required; pre-existing EC2 key pair */
    const char *subnet_id;             /* required; infra stack output */
    const char *security_group_id;     /* required; infra stack output */
    const char *instance_profile_name; /* required; IamInstanceProfile.Name */
    const char *client_token;          /* required, 1..64 chars; idempotency */
    const char *project;               /* required; Project tag */
    const char *name;                  /* required; Name tag (the FQDN) */
    const char *launch_nonce;          /* required; stackctl:launch-nonce tag */
    const char *root_device_name;      /* required; from ec2_image */
    const char *root_volume_type;      /* NULL => "gp3" */
    int root_volume_size_gb;           /* required; > 0 */
    int spot;                          /* non-zero => one-time spot, terminate on interruption */
} ec2_run_spec;

/* RunInstances result (first instance; MinCount=MaxCount=1). */
typedef struct ec2_run_result {
    char instance_id[EC2_INSTANCE_ID_MAX];
    char state[EC2_STATE_NAME_MAX];
    char private_ip[EC2_IP_MAX];
    char public_ip[EC2_IP_MAX];
} ec2_run_result;

/* One instance in a TerminateInstances response. */
typedef struct ec2_terminate_entry {
    char instance_id[EC2_INSTANCE_ID_MAX];
    char state[EC2_STATE_NAME_MAX];
} ec2_terminate_entry;

typedef struct ec2_terminate_result {
    ec2_terminate_entry *items;
    size_t count;
} ec2_terminate_result;

/* Opaque client: aws_ctx + fixed region + transport seam. */
typedef struct ec2_client ec2_client;

/*
 * Create a client bound to `aws` and `region`. `region` is copied. The client
 * borrows `aws` and never frees it. Returns 0, else EINVAL/ENOMEM.
 */
int ec2_client_init(ec2_client **out, aws_ctx *aws, const char *region);

/* Release a client from ec2_client_init(). Safe on NULL. */
void ec2_client_free(ec2_client *client);

/*
 * Launch exactly one instance.
 *
 * Invariants encoded in the request (spec §4):
 *   - MinCount=MaxCount=1 and ClientToken (AWS dedupes retries for 24 h);
 *   - TagSpecifications on the *instance resource only*, carrying exactly the
 *     Project, Name and stackctl:launch-nonce tags;
 *   - root EBS volume of `root_volume_size_gb` / root_volume_type, always
 *     Encrypted=true and DeleteOnTermination=true;
 *   - spot => InstanceMarketOptions.MarketType=spot with one-time
 *     InstanceInterruptionBehavior=terminate, and *no* MaxPrice;
 *   - IamInstanceProfile.Name = instance_profile_name;
 *   - MetadataOptions.HttpEndpoint=enabled, HttpTokens=required and
 *     HttpPutResponseHopLimit=2 (IMDSv2 launch invariant, spec §9).
 *
 * Returns 0, EC2_ERR_AWS_API on an AWS error (capacity rejections carry the
 * spec §4 hint), EINVAL on invalid input, or another errno-style code.
 */
int ec2_run_instances(ec2_client *client, const ec2_run_spec *spec,
                      ec2_run_result *out);

/*
 * Describe instances with `filter_count` AND-combined filters. A NULL filter
 * list describes every instance in the region. `out` receives a heap-owned
 * list (ec2_instance_list_free()). Returns 0, EC2_ERR_AWS_API, EBADMSG on an
 * unparseable response, EINVAL, or another errno-style code.
 */
int ec2_describe_instances(ec2_client *client, const ec2_filter *filters,
                           size_t filter_count, ec2_instance_list *out);

/*
 * Describe images by id (preflight: the effective AMI must resolve in the
 * region). `out` receives a heap-owned list (ec2_image_list_free()); zero
 * matches is success with count 0, the caller decides whether that is fatal.
 */
int ec2_describe_images(ec2_client *client, const char *const *image_ids,
                        size_t image_id_count, ec2_image_list *out);

/*
 * Terminate the given instances. Termination itself is idempotent at AWS;
 * `out` receives each instance's requested current state.
 */
int ec2_terminate_instances(ec2_client *client, const char *const *instance_ids,
                            size_t instance_id_count,
                            ec2_terminate_result *out);

/*
 * Fetch the instance console output (decoded from the API's base64) for
 * host-key fingerprint verification. On success `*output_out` is a
 * heap-allocated NUL-terminated string (free with ec2_string_free()), or NULL
 * when AWS returned no output yet. Returns 0, EC2_ERR_AWS_API, or an
 * errno-style code.
 */
int ec2_get_console_output(ec2_client *client, const char *instance_id,
                           char **output_out);

/* CreateTags: apply `tag_count` tags to every listed instance. */
int ec2_tag_instances(ec2_client *client, const char *const *instance_ids,
                      size_t instance_id_count, const ec2_tag *tags,
                      size_t tag_count);

/* DeleteTags: remove the named tag keys from every listed instance. */
int ec2_untag_instances(ec2_client *client, const char *const *instance_ids,
                        size_t instance_id_count,
                        const char *const *tag_keys, size_t tag_key_count);

/*
 * Poll until `instance_id` is `running` and has a public IP, using `aws_wait`
 * (spec §4 instance-ready waiter: 300 s default upstream). `out` receives the
 * last observed instance (zeroed when never observed). Returns 0 with
 * `*timed_out == 0` on success, 0 with `*timed_out == 1` on exhaustion, or a
 * propagated error code.
 */
int ec2_wait_running_with_public_ip(ec2_client *client, const char *instance_id,
                                    int attempts, int interval_sec,
                                    ec2_instance *out, int *timed_out);

/*
 * Poll until every listed instance is `terminated` (or no longer visible),
 * using `aws_wait` (spec §4 terminate waiter: bounded ~300 s upstream).
 * Returns 0/`*timed_out` like the running waiter.
 */
int ec2_wait_terminated(ec2_client *client, const char *const *instance_ids,
                        size_t instance_id_count, int attempts,
                        int interval_sec, int *timed_out);

/* Return the value of the tag `key` on `instance`, or NULL when absent. */
const char *ec2_instance_tag(const ec2_instance *instance, const char *key);

/* Destructors. All are safe on NULL or zeroed values. */
void ec2_instance_list_free(ec2_instance_list *list);
void ec2_image_list_free(ec2_image_list *list);
void ec2_terminate_result_free(ec2_terminate_result *result);
void ec2_string_free(char *string);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_EC2_EC2_H */
