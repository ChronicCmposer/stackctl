/*
 * ssm.c — AWS Systems Manager (Parameter Store + Run Command) over core/aws.
 *
 * The SSM API is JSON-1.1: `POST /` with `Content-Type:
 * application/x-amz-json-1.1` and `X-Amz-Target: AmazonSSM.<Operation>`.
 * Requests are built with yyjson and responses parsed with the same document
 * that core/aws caches on the response. No sockets are opened here.
 */

#include "ssm_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yyjson.h"

/* --- client ------------------------------------------------------------- */

static int aws_transport(aws_ctx *aws, const ssm_call *call, aws_resp *resp,
                         void *ud)
{
    (void)ud;
    if (aws == NULL || call == NULL || resp == NULL) {
        return EINVAL;
    }
    /* `call->req` already carries X-Amz-Target and Content-Type as extra
     * headers (CONTRACT Amendment 5); core/aws signs the x-amz-* extras. */
    return aws_request(aws, &call->req, resp);
}

int ssm_client_init_with_transport(ssm_client **out, aws_ctx *aws,
                                   const char *region,
                                   ssm_transport_fn transport, void *ud)
{
    if (out == NULL || region == NULL || region[0] == '\0' ||
        transport == NULL) {
        return EINVAL;
    }
    ssm_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return ENOMEM;
    }
    client->aws = aws;
    snprintf(client->region, sizeof(client->region), "%s", region);
    client->transport = transport;
    client->transport_ud = ud;
    *out = client;
    return 0;
}

int ssm_client_init(ssm_client **out, aws_ctx *aws, const char *region)
{
    if (aws == NULL) {
        return EINVAL;
    }
    return ssm_client_init_with_transport(out, aws, region, aws_transport, NULL);
}

void ssm_client_free(ssm_client *client)
{
    free(client);
}

/* --- shared helpers ----------------------------------------------------- */

int ssm_build_target(const char *operation, char *out, size_t out_size)
{
    if (operation == NULL || operation[0] == '\0' || out == NULL ||
        out_size == 0) {
        return EINVAL;
    }
    int need = snprintf(out, out_size, "%s%s", SSM_TARGET_PREFIX, operation);
    if (need < 0) {
        return EINVAL;
    }
    if ((size_t)need >= out_size) {
        out[0] = '\0';
        return EFBIG;
    }
    return 0;
}

int ssm_build_headers(const char *operation, char *target_header,
                      size_t target_header_size,
                      const char *out[SSM_EXTRA_HEADER_COUNT])
{
    static const char content_type_header[] =
        "Content-Type: " SSM_API_CONTENT_TYPE;

    if (target_header == NULL || out == NULL) {
        return EINVAL;
    }
    char target[SSM_TARGET_HEADER_MAX];
    int rc = ssm_build_target(operation, target, sizeof(target));
    if (rc != 0) {
        return rc;
    }
    int need = snprintf(target_header, target_header_size, "X-Amz-Target: %s",
                        target);
    if (need < 0) {
        return EINVAL;
    }
    if ((size_t)need >= target_header_size) {
        target_header[0] = '\0';
        return EFBIG;
    }
    out[0] = target_header;
    out[1] = content_type_header;
    return 0;
}

int ssm_status_to_errno(long status, const char *code)
{
    if (status >= 200 && status < 300) {
        return 0;
    }
    if (code != NULL) {
        if (strcmp(code, "ParameterNotFound") == 0 ||
            strcmp(code, "ParameterVersionNotFound") == 0 ||
            strcmp(code, "InvocationDoesNotExist") == 0) {
            return ENOENT;
        }
        if (strcmp(code, "AccessDeniedException") == 0 ||
            strcmp(code, "AccessDenied") == 0) {
            return EACCES;
        }
    }
    return SSM_ERR_AWS_API;
}

/* Build the request body and release `doc`; on success `*json` is heap-owned. */
static int json_finish(yyjson_mut_doc *doc, char **json, size_t *json_len)
{
    *json = yyjson_mut_write(doc, 0, json_len);
    yyjson_mut_doc_free(doc);
    return *json == NULL ? ENOMEM : 0;
}

static void report_api_error(const char *operation, long status,
                             const char *code, const char *message)
{
    if (code != NULL && code[0] != '\0' && message != NULL &&
        message[0] != '\0') {
        fprintf(stderr, "stackctl: SSM %s failed: %s: %s\n", operation, code,
                message);
    } else if (code != NULL && code[0] != '\0') {
        fprintf(stderr, "stackctl: SSM %s failed: %s\n", operation, code);
    } else {
        fprintf(stderr, "stackctl: SSM %s failed: HTTP %ld\n", operation,
                status);
    }
}

/*
 * Issue one SSM JSON operation. On an HTTP error response this reports the AWS
 * error to stderr (except the benign InvocationDoesNotExist) and returns the
 * mapped errno-style code. On success `resp` is populated; the caller frees it.
 */
static int ssm_call_api(ssm_client *client, const char *operation,
                        const char *body, size_t body_len, aws_resp *resp)
{
    memset(resp, 0, sizeof(*resp));
    char target[128];
    int rc = ssm_build_target(operation, target, sizeof(target));
    if (rc != 0) {
        return rc;
    }

    ssm_call call;
    memset(&call, 0, sizeof(call));

    char target_header[SSM_TARGET_HEADER_MAX];
    const char *headers[SSM_EXTRA_HEADER_COUNT];
    rc = ssm_build_headers(operation, target_header, sizeof(target_header),
                           headers);
    if (rc != 0) {
        return rc;
    }

    call.req.service = "ssm";
    call.req.region = client->region;
    call.req.method = "POST";
    call.req.path = "/";
    call.req.query = NULL;
    call.req.body = body;
    call.req.body_len = body_len;
    /* Content-Type travels as a signed extra header (Amendment 5), so leave
     * the unsigned `content_type` field unset to avoid a duplicate line. */
    call.req.content_type = NULL;
    call.req.unsigned_payload = 0;
    call.req.extra_headers = headers;
    call.req.extra_header_count = SSM_EXTRA_HEADER_COUNT;
    call.target = target;

    rc = client->transport(client->aws, &call, resp, client->transport_ud);
    if (rc != 0) {
        return rc;
    }

    if (resp->status >= 200 && resp->status < 300) {
        return 0;
    }

    char code[SSM_ERROR_CODE_MAX];
    char message[512];
    code[0] = '\0';
    message[0] = '\0';
    aws_error_code(resp, code);
    yyjson_doc *doc = aws_resp_json(resp);
    if (doc != NULL) {
        yyjson_val *root = yyjson_doc_get_root(doc);
        yyjson_val *value = yyjson_obj_get(root, "message");
        if (value == NULL) {
            value = yyjson_obj_get(root, "Message");
        }
        if (value != NULL && yyjson_is_str(value)) {
            snprintf(message, sizeof(message), "%s", yyjson_get_str(value));
        }
    }

    int mapped = ssm_status_to_errno(resp->status, code);
    if (strcmp(code, "InvocationDoesNotExist") != 0) {
        report_api_error(operation, resp->status, code, message);
    }
    return mapped;
}

/* Copy an optional string field. Returns 0 with *out NULL when absent. */
static int json_dup_string(yyjson_val *obj, const char *key, char **out)
{
    *out = NULL;
    yyjson_val *value = yyjson_obj_get(obj, key);
    if (value == NULL || yyjson_is_null(value)) {
        return 0;
    }
    if (!yyjson_is_str(value)) {
        return EBADMSG;
    }
    char *copy = strdup(yyjson_get_str(value));
    if (copy == NULL) {
        return ENOMEM;
    }
    *out = copy;
    return 0;
}

/* Copy a string field into a fixed buffer, leaving it empty when absent. */
static void json_copy_string(yyjson_val *obj, const char *key, char *out,
                             size_t out_size)
{
    yyjson_val *value = yyjson_obj_get(obj, key);
    if (value != NULL && yyjson_is_str(value)) {
        snprintf(out, out_size, "%s", yyjson_get_str(value));
    }
}

/* --- Parameter Store --------------------------------------------------- */

int ssm_get_parameter(ssm_client *client, const char *name, int with_decryption,
                      ssm_parameter *out)
{
    if (client == NULL || name == NULL || name[0] != '/' || out == NULL) {
        return EINVAL;
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        return ENOMEM;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_str(doc, root, "Name", name) &&
              yyjson_mut_obj_add_bool(doc, root, "WithDecryption",
                                      with_decryption != 0);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ENOMEM;
    }

    char *body = NULL;
    size_t body_len = 0;
    int rc = json_finish(doc, &body, &body_len);
    if (rc != 0) {
        return rc;
    }

    aws_resp resp = {0};
    rc = ssm_call_api(client, "GetParameter", body, body_len, &resp);
    free(body);
    if (rc != 0) {
        aws_resp_free(&resp);
        return rc;
    }

    yyjson_doc *response = aws_resp_json(&resp);
    yyjson_val *response_root =
        response != NULL ? yyjson_doc_get_root(response) : NULL;
    yyjson_val *parameter = response_root != NULL
                                ? yyjson_obj_get(response_root, "Parameter")
                                : NULL;
    if (!yyjson_is_obj(parameter)) {
        aws_resp_free(&resp);
        return EBADMSG;
    }

    ssm_parameter parsed;
    memset(&parsed, 0, sizeof(parsed));
    rc = json_dup_string(parameter, "Name", &parsed.name);
    if (rc == 0 && parsed.name == NULL) {
        rc = EBADMSG;
    }
    if (rc == 0) {
        rc = json_dup_string(parameter, "Value", &parsed.value);
        if (rc == 0 && parsed.value == NULL) {
            rc = EBADMSG;
        }
    }
    if (rc == 0) {
        rc = json_dup_string(parameter, "Type", &parsed.type);
    }
    if (rc == 0) {
        rc = json_dup_string(parameter, "ARN", &parsed.arn);
    }
    if (rc == 0) {
        rc = json_dup_string(parameter, "DataType", &parsed.data_type);
    }
    if (rc != 0) {
        ssm_parameter_free(&parsed);
        aws_resp_free(&resp);
        return rc;
    }

    yyjson_val *version = yyjson_obj_get(parameter, "Version");
    if (version != NULL && yyjson_is_int(version)) {
        parsed.version = (long)yyjson_get_int(version);
    }
    json_copy_string(parameter, "LastModifiedDate", parsed.last_modified,
                     sizeof(parsed.last_modified));

    *out = parsed;
    aws_resp_free(&resp);
    return 0;
}

void ssm_parameter_free(ssm_parameter *parameter)
{
    if (parameter == NULL) {
        return;
    }
    free(parameter->name);
    free(parameter->type);
    free(parameter->value);
    free(parameter->arn);
    free(parameter->data_type);
    memset(parameter, 0, sizeof(*parameter));
}

/* --- Run Command: SendCommand ------------------------------------------ */

static int valid_string_list(const char *const *items, size_t count)
{
    if (items == NULL || count == 0) {
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        if (items[i] == NULL || items[i][0] == '\0') {
            return 0;
        }
    }
    return 1;
}

int ssm_send_command(ssm_client *client, const ssm_send_spec *spec,
                     ssm_send_result *out)
{
    if (client == NULL || spec == NULL || out == NULL) {
        return EINVAL;
    }
    if (!valid_string_list(spec->commands, spec->command_count) ||
        !valid_string_list(spec->instance_ids, spec->instance_id_count)) {
        return EINVAL;
    }
    if (spec->document_name != NULL && spec->document_name[0] == '\0') {
        return EINVAL;
    }

    const char *document = spec->document_name != NULL
                               ? spec->document_name
                               : SSM_DOCUMENT_RUN_SHELL_SCRIPT;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        return ENOMEM;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);

    bool ok = yyjson_mut_obj_add_str(doc, root, "DocumentName", document);
    yyjson_mut_val *instances = yyjson_mut_arr(doc);
    yyjson_mut_val *parameters = yyjson_mut_obj(doc);
    yyjson_mut_val *commands = yyjson_mut_arr(doc);
    ok = ok && instances != NULL && parameters != NULL && commands != NULL;

    for (size_t i = 0; ok && i < spec->instance_id_count; i++) {
        ok = yyjson_mut_arr_add_str(doc, instances, spec->instance_ids[i]);
    }
    for (size_t i = 0; ok && i < spec->command_count; i++) {
        ok = yyjson_mut_arr_add_str(doc, commands, spec->commands[i]);
    }
    ok = ok && yyjson_mut_obj_add_val(doc, parameters, "commands", commands);
    ok = ok && yyjson_mut_obj_add_val(doc, root, "InstanceIds", instances);
    ok = ok && yyjson_mut_obj_add_val(doc, root, "Parameters", parameters);
    if (ok && spec->timeout_seconds > 0) {
        ok = yyjson_mut_obj_add_int(doc, root, "TimeoutSeconds",
                                    spec->timeout_seconds);
    }
    if (ok && spec->comment != NULL) {
        ok = yyjson_mut_obj_add_str(doc, root, "Comment", spec->comment);
    }
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ENOMEM;
    }

    char *body = NULL;
    size_t body_len = 0;
    int rc = json_finish(doc, &body, &body_len);
    if (rc != 0) {
        return rc;
    }

    aws_resp resp = {0};
    rc = ssm_call_api(client, "SendCommand", body, body_len, &resp);
    free(body);
    if (rc != 0) {
        aws_resp_free(&resp);
        return rc;
    }

    yyjson_doc *response = aws_resp_json(&resp);
    yyjson_val *response_root =
        response != NULL ? yyjson_doc_get_root(response) : NULL;
    yyjson_val *command = response_root != NULL
                              ? yyjson_obj_get(response_root, "Command")
                              : NULL;
    char *command_id = NULL;
    if (yyjson_is_obj(command)) {
        rc = json_dup_string(command, "CommandId", &command_id);
    } else {
        rc = EBADMSG;
    }
    if (rc == 0 && command_id == NULL) {
        rc = EBADMSG;
    }
    if (rc == 0) {
        memset(out, 0, sizeof(*out));
        snprintf(out->command_id, sizeof(out->command_id), "%s", command_id);
    }
    free(command_id);
    aws_resp_free(&resp);
    return rc;
}

/* --- Run Command: GetCommandInvocation --------------------------------- */

int ssm_get_command_invocation(ssm_client *client, const char *command_id,
                               const char *instance_id, ssm_invocation *out)
{
    if (client == NULL || command_id == NULL || command_id[0] == '\0' ||
        instance_id == NULL || instance_id[0] == '\0' || out == NULL) {
        return EINVAL;
    }

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (doc == NULL) {
        return ENOMEM;
    }
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_str(doc, root, "CommandId", command_id) &&
              yyjson_mut_obj_add_str(doc, root, "InstanceId", instance_id);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ENOMEM;
    }

    char *body = NULL;
    size_t body_len = 0;
    int rc = json_finish(doc, &body, &body_len);
    if (rc != 0) {
        return rc;
    }

    aws_resp resp = {0};
    rc = ssm_call_api(client, "GetCommandInvocation", body, body_len, &resp);
    free(body);
    if (rc != 0) {
        aws_resp_free(&resp);
        return rc;
    }

    yyjson_doc *response = aws_resp_json(&resp);
    yyjson_val *response_root =
        response != NULL ? yyjson_doc_get_root(response) : NULL;
    yyjson_val *status = response_root != NULL
                             ? yyjson_obj_get(response_root, "Status")
                             : NULL;
    if (!yyjson_is_str(status)) {
        aws_resp_free(&resp);
        return EBADMSG;
    }

    ssm_invocation parsed;
    memset(&parsed, 0, sizeof(parsed));
    parsed.response_code = -1;
    json_copy_string(response_root, "CommandId", parsed.command_id,
                     sizeof(parsed.command_id));
    json_copy_string(response_root, "InstanceId", parsed.instance_id,
                     sizeof(parsed.instance_id));
    json_copy_string(response_root, "Status", parsed.status,
                     sizeof(parsed.status));
    json_copy_string(response_root, "StatusDetails", parsed.status_details,
                     sizeof(parsed.status_details));
    parsed.state = ssm_command_status_parse(parsed.status);

    rc = json_dup_string(response_root, "StandardOutputContent",
                         &parsed.standard_output);
    if (rc == 0) {
        rc = json_dup_string(response_root, "StandardErrorContent",
                             &parsed.standard_error);
    }
    if (rc != 0) {
        ssm_invocation_free(&parsed);
        aws_resp_free(&resp);
        return rc;
    }

    yyjson_val *response_code = yyjson_obj_get(response_root, "ResponseCode");
    if (response_code != NULL && yyjson_is_int(response_code)) {
        parsed.response_code = (long)yyjson_get_int(response_code);
    }

    *out = parsed;
    aws_resp_free(&resp);
    return 0;
}

void ssm_invocation_free(ssm_invocation *invocation)
{
    if (invocation == NULL) {
        return;
    }
    free(invocation->standard_output);
    free(invocation->standard_error);
    memset(invocation, 0, sizeof(*invocation));
}

/* --- Run Command: bounded polling -------------------------------------- */

typedef struct wait_state {
    ssm_client *client;
    const char *command_id;
    const char *instance_id;
    ssm_invocation *out;
} wait_state;

static int wait_poll(aws_ctx *aws, void *ud, int *done)
{
    (void)aws;
    wait_state *state = ud;
    ssm_invocation observed;
    memset(&observed, 0, sizeof(observed));

    int rc = ssm_get_command_invocation(state->client, state->command_id,
                                        state->instance_id, &observed);
    if (rc == ENOENT) {
        /* The command has not reached the instance yet: keep polling. */
        *done = 0;
        return 0;
    }
    if (rc != 0) {
        return rc;
    }

    ssm_invocation_free(state->out);
    *state->out = observed;
    *done = ssm_command_status_terminal(observed.state);
    return 0;
}

int ssm_wait_command(ssm_client *client, const char *command_id,
                     const char *instance_id, int attempts, int interval_sec,
                     ssm_invocation *out, int *timed_out)
{
    if (client == NULL || command_id == NULL || command_id[0] == '\0' ||
        instance_id == NULL || instance_id[0] == '\0' || out == NULL ||
        timed_out == NULL || attempts < 1) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    wait_state state = {
        .client = client,
        .command_id = command_id,
        .instance_id = instance_id,
        .out = out,
    };
    return aws_wait(client->aws, wait_poll, &state, attempts, interval_sec,
                    timed_out);
}

/* --- status mapping ---------------------------------------------------- */

struct status_entry {
    const char *name;
    ssm_command_status status;
};

static const struct status_entry status_table[] = {
    {"Pending", SSM_COMMAND_PENDING},
    {"InProgress", SSM_COMMAND_IN_PROGRESS},
    {"Delayed", SSM_COMMAND_DELAYED},
    {"Success", SSM_COMMAND_SUCCESS},
    {"Cancelled", SSM_COMMAND_CANCELLED},
    {"TimedOut", SSM_COMMAND_TIMED_OUT},
    {"Failed", SSM_COMMAND_FAILED},
    {"Cancelling", SSM_COMMAND_CANCELLING},
};

ssm_command_status ssm_command_status_parse(const char *status)
{
    if (status == NULL) {
        return SSM_COMMAND_UNKNOWN;
    }
    for (size_t i = 0; i < sizeof(status_table) / sizeof(status_table[0]);
         i++) {
        if (strcmp(status, status_table[i].name) == 0) {
            return status_table[i].status;
        }
    }
    return SSM_COMMAND_UNKNOWN;
}

const char *ssm_command_status_name(ssm_command_status status)
{
    for (size_t i = 0; i < sizeof(status_table) / sizeof(status_table[0]);
         i++) {
        if (status_table[i].status == status) {
            return status_table[i].name;
        }
    }
    return "Unknown";
}

int ssm_command_status_terminal(ssm_command_status status)
{
    switch (status) {
    case SSM_COMMAND_SUCCESS:
    case SSM_COMMAND_CANCELLED:
    case SSM_COMMAND_TIMED_OUT:
    case SSM_COMMAND_FAILED:
        return 1;
    default:
        return 0;
    }
}
