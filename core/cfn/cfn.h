/*
 * cfn.h — CloudFormation request builder + response parser (spec §4, §6;
 * CONTRACT.md §core/cfn).
 *
 * Every operation is an AWS Query-protocol call (`POST /`, form-encoded body
 * with `Action` + `Version=2010-05-15`, XML response) issued through
 * core/aws's single HTTP seam. This module owns request shapes, XML parsing,
 * stack/change-set status mapping, error translation and bounded waiters; it
 * never owns credentials, transport or retry policy.
 *
 * Error model (CONTRACT.md): 0 on success, non-zero errno-style otherwise.
 * Local argument problems yield EINVAL. Errors returned by AWS are translated:
 *   ENOENT  stack/change set does not exist
 *   EEXIST  resource already exists
 *   EALREADY "No updates are to be performed" (an *empty change set* is a
 *           normal result, not an error — inspect change_count)
 *   EACCES  access denied
 *   EPERM   insufficient capabilities
 *   EBUSY   throttling that survived transport retries
 *   EIO     any other AWS API error
 *   ECANCELED  a waiter observed a terminal failure stack/change-set state
 * Transport-level codes from aws_request() are propagated unchanged.
 * Callers must classify any non-zero return from an AWS-bound call as the
 * spec's exit 2 (AWS API error), never as a usage error.
 *
 * Diagnostics (the AWS error code/message, waiter failure reason) go to
 * stderr only.
 */

#ifndef STACKCTL_CORE_CFN_CFN_H
#define STACKCTL_CORE_CFN_CFN_H

#include <stddef.h>

#include "../aws/aws.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CFN_STACK_NAME_MAX 129
#define CFN_STACK_ID_MAX 512
#define CFN_STATUS_REASON_MAX 2048
#define CFN_DESCRIPTION_MAX 1024
#define CFN_PARAMETER_KEY_MAX 256
#define CFN_PARAMETER_VALUE_MAX 4096
#define CFN_OUTPUT_KEY_MAX 256
#define CFN_OUTPUT_VALUE_MAX 4096
#define CFN_TAG_KEY_MAX 128
#define CFN_TAG_VALUE_MAX 256
#define CFN_CHANGE_SET_NAME_MAX 128
#define CFN_CHANGE_SET_ID_MAX 512
#define CFN_CHANGE_ACTION_MAX 16
#define CFN_CHANGE_REPLACEMENT_MAX 16
#define CFN_LOGICAL_ID_MAX 256
#define CFN_PHYSICAL_ID_MAX 512
#define CFN_RESOURCE_TYPE_MAX 256
#define CFN_RESOURCE_STATUS_MAX 64
#define CFN_EVENT_ID_MAX 64
#define CFN_TIMESTAMP_MAX 40
#define CFN_TEMPLATE_DEFAULT_MAX 4096
#define CFN_TEMPLATE_TYPE_MAX 128
#define CFN_CAPABILITY_NAME_MAX 64
#define CFN_RESOURCE_TYPE_NAME_MAX 128

/* Capabilities accepted by CreateChangeSet (bit flags, OR-ed). */
#define CFN_CAPABILITY_IAM 0x1u
#define CFN_CAPABILITY_NAMED_IAM 0x2u
#define CFN_CAPABILITY_AUTO_EXPAND 0x4u

/* Opaque client: an aws_ctx plus the request seam (fake in unit tests). */
typedef struct cfn_client cfn_client;

/*
 * Create/destroy a client bound to an initialized aws_ctx. `region` is passed
 * per operation (a project can target several regions with one client).
 * Returns 0, EINVAL or ENOMEM.
 */
int cfn_client_create(cfn_client **out, aws_ctx *aws);
void cfn_client_destroy(cfn_client *client);

/* ------------------------------------------------------------------ status */

/* Stack status values mirrored from the CloudFormation API. */
typedef enum cfn_stack_status {
    CFN_STACK_STATUS_UNKNOWN = 0,
    CFN_STACK_STATUS_CREATE_IN_PROGRESS,
    CFN_STACK_STATUS_CREATE_FAILED,
    CFN_STACK_STATUS_CREATE_COMPLETE,
    CFN_STACK_STATUS_ROLLBACK_IN_PROGRESS,
    CFN_STACK_STATUS_ROLLBACK_FAILED,
    CFN_STACK_STATUS_ROLLBACK_COMPLETE,
    CFN_STACK_STATUS_DELETE_IN_PROGRESS,
    CFN_STACK_STATUS_DELETE_FAILED,
    CFN_STACK_STATUS_DELETE_COMPLETE,
    CFN_STACK_STATUS_UPDATE_IN_PROGRESS,
    CFN_STACK_STATUS_UPDATE_COMPLETE_CLEANUP_IN_PROGRESS,
    CFN_STACK_STATUS_UPDATE_COMPLETE,
    CFN_STACK_STATUS_UPDATE_FAILED,
    CFN_STACK_STATUS_UPDATE_ROLLBACK_IN_PROGRESS,
    CFN_STACK_STATUS_UPDATE_ROLLBACK_FAILED,
    CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS,
    CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE,
    CFN_STACK_STATUS_REVIEW_IN_PROGRESS,
    CFN_STACK_STATUS_IMPORT_IN_PROGRESS,
    CFN_STACK_STATUS_IMPORT_COMPLETE,
    CFN_STACK_STATUS_IMPORT_ROLLBACK_IN_PROGRESS,
    CFN_STACK_STATUS_IMPORT_ROLLBACK_FAILED,
    CFN_STACK_STATUS_IMPORT_ROLLBACK_COMPLETE
} cfn_stack_status;

const char *cfn_stack_status_string(cfn_stack_status status);
/* Parse an API status token; *out = UNKNOWN when the token is not recognised
 * (a future AWS status must not crash the CLI). */
int cfn_stack_status_parse(const char *name, cfn_stack_status *out);
/* True for any *_IN_PROGRESS state (spec §4 "another operation in progress"). */
int cfn_stack_status_is_in_progress(cfn_stack_status status);
/* Spec §4 healthy/updatable set: CREATE_COMPLETE, UPDATE_COMPLETE,
 * UPDATE_ROLLBACK_COMPLETE. */
int cfn_stack_status_is_healthy(cfn_stack_status status);

typedef enum cfn_change_set_status {
    CFN_CHANGE_SET_STATUS_UNKNOWN = 0,
    CFN_CHANGE_SET_STATUS_CREATE_PENDING,
    CFN_CHANGE_SET_STATUS_CREATE_IN_PROGRESS,
    CFN_CHANGE_SET_STATUS_CREATE_COMPLETE,
    CFN_CHANGE_SET_STATUS_DELETE_PENDING,
    CFN_CHANGE_SET_STATUS_DELETE_IN_PROGRESS,
    CFN_CHANGE_SET_STATUS_DELETE_COMPLETE,
    CFN_CHANGE_SET_STATUS_DELETE_FAILED,
    CFN_CHANGE_SET_STATUS_FAILED
} cfn_change_set_status;

typedef enum cfn_change_set_execution_status {
    CFN_CHANGE_SET_EXECUTION_UNKNOWN = 0,
    CFN_CHANGE_SET_EXECUTION_UNAVAILABLE,
    CFN_CHANGE_SET_EXECUTION_AVAILABLE,
    CFN_CHANGE_SET_EXECUTION_IN_PROGRESS,
    CFN_CHANGE_SET_EXECUTION_COMPLETE,
    CFN_CHANGE_SET_EXECUTION_FAILED,
    CFN_CHANGE_SET_EXECUTION_OBSOLETE
} cfn_change_set_execution_status;

const char *cfn_change_set_status_string(cfn_change_set_status status);
int cfn_change_set_status_parse(const char *name, cfn_change_set_status *out);
const char *cfn_change_set_execution_status_string(
    cfn_change_set_execution_status status);
int cfn_change_set_execution_status_parse(
    const char *name, cfn_change_set_execution_status *out);

/* ------------------------------------------------------------------- types */

typedef struct cfn_parameter {
    char key[CFN_PARAMETER_KEY_MAX];
    char value[CFN_PARAMETER_VALUE_MAX];
    int use_previous_value; /* request-only; parsed responses leave it 0 */
} cfn_parameter;

typedef struct cfn_tag {
    char key[CFN_TAG_KEY_MAX];
    char value[CFN_TAG_VALUE_MAX];
} cfn_tag;

typedef struct cfn_output {
    char key[CFN_OUTPUT_KEY_MAX];
    char value[CFN_OUTPUT_VALUE_MAX];
    char description[CFN_DESCRIPTION_MAX];
} cfn_output;

typedef struct cfn_stack {
    char stack_name[CFN_STACK_NAME_MAX];
    char stack_id[CFN_STACK_ID_MAX];
    cfn_stack_status status;
    char status_reason[CFN_STATUS_REASON_MAX];
    cfn_parameter *parameters;
    size_t parameter_count;
    cfn_output *outputs;
    size_t output_count;
    cfn_tag *tags;
    size_t tag_count;
} cfn_stack;

typedef struct cfn_stack_list {
    cfn_stack *items;
    size_t count;
} cfn_stack_list;

void cfn_stack_list_free(cfn_stack_list *list);

/* Lookup helpers; return NULL when absent. */
const char *cfn_stack_output(const cfn_stack *stack, const char *key);
const char *cfn_stack_parameter(const cfn_stack *stack, const char *key);
const char *cfn_stack_tag(const cfn_stack *stack, const char *key);

/* ---------------------------------------------------------- describe stacks */

/*
 * DescribeStacks. `stack_name` NULL lists every stack in the region
 * (paginated); a name returns that stack or ENOENT. `out` is heap-owned and
 * must be released with cfn_stack_list_free().
 */
int cfn_describe_stacks(cfn_client *client, const char *region,
                        const char *stack_name, cfn_stack_list *out);

/* ------------------------------------------------------------- change sets */

typedef enum cfn_change_set_type {
    CFN_CHANGE_SET_TYPE_CREATE = 1,
    CFN_CHANGE_SET_TYPE_UPDATE = 2
} cfn_change_set_type;

typedef struct cfn_change_set_spec {
    const char *stack_name;       /* required */
    const char *change_set_name;  /* required */
    const char *template_body;    /* required: JSON or YAML text */
    cfn_change_set_type type;     /* CREATE or UPDATE */
    const cfn_parameter *parameters; /* may be NULL */
    size_t parameter_count;
    const cfn_tag *tags;          /* stack tags; may be NULL */
    size_t tag_count;
    const char *description;      /* optional */
    unsigned capabilities;        /* CFN_CAPABILITY_* flags */
} cfn_change_set_spec;

typedef struct cfn_change_set_result {
    char change_set_id[CFN_CHANGE_SET_ID_MAX];
    char stack_id[CFN_STACK_ID_MAX];
} cfn_change_set_result;

/*
 * CreateChangeSet — the create-or-update path used by provision and deploy.
 * For CFN_CHANGE_SET_TYPE_UPDATE when the stack does not exist use CREATE.
 * AWS returns asynchronously: poll with cfn_wait_for_change_set() before
 * describing/executing.
 */
int cfn_create_change_set(cfn_client *client, const char *region,
                          const cfn_change_set_spec *spec,
                          cfn_change_set_result *out);

typedef struct cfn_change {
    char action[CFN_CHANGE_ACTION_MAX]; /* Add | Modify | Remove */
    char logical_resource_id[CFN_LOGICAL_ID_MAX];
    char physical_resource_id[CFN_PHYSICAL_ID_MAX];
    char resource_type[CFN_RESOURCE_TYPE_MAX];
    char replacement[CFN_CHANGE_REPLACEMENT_MAX]; /* True|False|Conditional */
} cfn_change;

typedef struct cfn_change_set {
    char change_set_id[CFN_CHANGE_SET_ID_MAX];
    char change_set_name[CFN_CHANGE_SET_NAME_MAX];
    char stack_id[CFN_STACK_ID_MAX];
    char stack_name[CFN_STACK_NAME_MAX];
    cfn_change_set_status status;
    char status_reason[CFN_STATUS_REASON_MAX];
    cfn_change_set_execution_status execution_status;
    cfn_change *changes; /* all pages accumulated */
    size_t change_count; /* 0 == empty change set */
} cfn_change_set;

void cfn_change_set_free(cfn_change_set *change_set);

/* DescribeChangeSet, following NextToken so change_count is complete. */
int cfn_describe_change_set(cfn_client *client, const char *region,
                            const char *stack_name, const char *change_set_name,
                            cfn_change_set *out);

int cfn_execute_change_set(cfn_client *client, const char *region,
                           const char *stack_name, const char *change_set_name);

/* DeleteChangeSet; a change set that is already gone returns 0 (idempotent). */
int cfn_delete_change_set(cfn_client *client, const char *region,
                          const char *stack_name, const char *change_set_name);

/* -------------------------------------------------------- template summary */

typedef struct cfn_template_parameter {
    char key[CFN_PARAMETER_KEY_MAX];
    char default_value[CFN_TEMPLATE_DEFAULT_MAX];
    char parameter_type[CFN_TEMPLATE_TYPE_MAX];
    char description[CFN_DESCRIPTION_MAX];
    int no_echo;
} cfn_template_parameter;

typedef struct cfn_string_list {
    char **items;
    size_t count;
} cfn_string_list;

typedef struct cfn_template_summary {
    cfn_template_parameter *parameters;
    size_t parameter_count;
    cfn_string_list capabilities;
    cfn_string_list resource_types;
    char description[CFN_DESCRIPTION_MAX];
} cfn_template_summary;

void cfn_template_summary_free(cfn_template_summary *summary);

/* GetTemplateSummary over an inline template body. */
int cfn_get_template_summary(cfn_client *client, const char *region,
                             const char *template_body,
                             cfn_template_summary *out);

/* -------------------------------------------------------------- operations */

/* DeleteStack; an already-absent stack returns 0 (idempotent teardown). */
int cfn_delete_stack(cfn_client *client, const char *region,
                     const char *stack_name);

typedef struct cfn_stack_resource {
    char logical_resource_id[CFN_LOGICAL_ID_MAX];
    char physical_resource_id[CFN_PHYSICAL_ID_MAX];
    char resource_type[CFN_RESOURCE_TYPE_MAX];
    char resource_status[CFN_RESOURCE_STATUS_MAX];
    char resource_status_reason[CFN_STATUS_REASON_MAX];
} cfn_stack_resource;

typedef struct cfn_stack_resource_list {
    cfn_stack_resource *items;
    size_t count;
} cfn_stack_resource_list;

void cfn_stack_resource_list_free(cfn_stack_resource_list *list);

/* DescribeStackResources — e.g. count resources to classify REVIEW_IN_PROGRESS
 * and name resources after DELETE_FAILED. */
int cfn_describe_stack_resources(cfn_client *client, const char *region,
                                 const char *stack_name,
                                 cfn_stack_resource_list *out);

typedef struct cfn_event {
    char event_id[CFN_EVENT_ID_MAX];
    char timestamp[CFN_TIMESTAMP_MAX];
    char logical_resource_id[CFN_LOGICAL_ID_MAX];
    char physical_resource_id[CFN_PHYSICAL_ID_MAX];
    char resource_type[CFN_RESOURCE_TYPE_MAX];
    char resource_status[CFN_RESOURCE_STATUS_MAX];
    char resource_status_reason[CFN_STATUS_REASON_MAX];
} cfn_event;

typedef struct cfn_event_list {
    cfn_event *items;
    size_t count;
} cfn_event_list;

void cfn_event_list_free(cfn_event_list *list);

/*
 * DescribeStackEvents, newest first (AWS order), following pages until
 * `max_events` entries are collected (0 = all pages, internally capped).
 */
int cfn_describe_stack_events(cfn_client *client, const char *region,
                              const char *stack_name, size_t max_events,
                              cfn_event_list *out);

/* ----------------------------------------------------------------- waiters */

typedef enum cfn_wait_operation {
    CFN_WAIT_CREATE = 1,
    CFN_WAIT_UPDATE = 2,
    CFN_WAIT_DELETE = 3
} cfn_wait_operation;

/*
 * Poll DescribeStacks through aws_wait() until the operation's terminal state.
 * Returns 0 on success (including `*timed_out == 1` when attempts are
 * exhausted), ECANCELED when the stack reached a terminal *failure* status
 * (the status and reason are printed to stderr), or a transport/API error.
 * For CFN_WAIT_DELETE an already-absent stack counts as success.
 */
int cfn_wait_for_stack(cfn_client *client, const char *region,
                       const char *stack_name, cfn_wait_operation operation,
                       int attempts, int interval_sec, int *timed_out);

/*
 * Poll DescribeChangeSet until CREATE_COMPLETE. ECANCELED on FAILED or a
 * deleted change set, with status reason on stderr.
 */
int cfn_wait_for_change_set(cfn_client *client, const char *region,
                            const char *stack_name, const char *change_set_name,
                            int attempts, int interval_sec, int *timed_out);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_CFN_CFN_H */
