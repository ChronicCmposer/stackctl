/*
 * ssm_test.c — unit tests for core/ssm over a fake transport.
 *
 * Every public function is exercised against the fake: tests assert the exact
 * X-Amz-Target, content type, JSON body and HTTP shape of each request, and the
 * parsed result / mapped error of each response. No socket is ever opened.
 */

#include "ssm.h"
#include "ssm_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yyjson.h"

static int failures;
static int checks;

#define CHECK(cond)                                                            \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                      \
    } while (0)

#define CHECK_STR(actual, expected)                                            \
    do {                                                                       \
        checks++;                                                              \
        const char *a_ = (actual);                                             \
        const char *e_ = (expected);                                           \
        if (a_ == NULL || strcmp(a_, e_) != 0) {                               \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: '%s' != '%s'\n", __FILE__, __LINE__,  \
                    a_ != NULL ? a_ : "(null)", e_);                           \
        }                                                                      \
    } while (0)

#define CHECK_INT(actual, expected)                                            \
    do {                                                                       \
        checks++;                                                              \
        long a_ = (long)(actual);                                              \
        long e_ = (long)(expected);                                            \
        if (a_ != e_) {                                                        \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %ld != %ld\n", __FILE__, __LINE__, a_, \
                    e_);                                                       \
        }                                                                      \
    } while (0)

/* --- fake transport ----------------------------------------------------- */

#define SCRIPT_MAX 8

typedef struct scripted_reply {
    long status;
    const char *body;
} scripted_reply;

typedef struct fake_transport {
    int calls;
    int transport_rc;

    char method[16];
    char path[256];
    char service[32];
    char region[SSM_REGION_MAX];
    char content_type[128];
    char target[128];
    size_t extra_header_count;
    char extra_headers[4][128];
    int has_query;
    int unsigned_payload;
    char *body;
    size_t body_len;

    scripted_reply script[SCRIPT_MAX];
    int script_count;
    int script_index;
} fake_transport;

static void fake_reset(fake_transport *f)
{
    free(f->body);
    memset(f, 0, sizeof(*f));
}

static void fake_queue(fake_transport *f, long status, const char *body)
{
    if (f->script_count >= SCRIPT_MAX) {
        return;
    }
    f->script[f->script_count].status = status;
    f->script[f->script_count].body = body;
    f->script_count++;
}

static void fake_reply(fake_transport *f, long status, const char *body)
{
    f->script_count = 0;
    fake_queue(f, status, body);
}

static int fake_send(aws_ctx *aws, const ssm_call *call, aws_resp *resp,
                     void *ud)
{
    (void)aws;
    fake_transport *f = ud;
    f->calls++;
    snprintf(f->method, sizeof(f->method), "%s", call->req.method);
    snprintf(f->path, sizeof(f->path), "%s", call->req.path);
    snprintf(f->service, sizeof(f->service), "%s", call->req.service);
    snprintf(f->region, sizeof(f->region), "%s", call->req.region);
    if (call->req.content_type != NULL) {
        snprintf(f->content_type, sizeof(f->content_type), "%s",
                 call->req.content_type);
    }
    if (call->target != NULL) {
        snprintf(f->target, sizeof(f->target), "%s", call->target);
    }
    f->extra_header_count = call->req.extra_header_count;
    for (size_t i = 0;
         i < call->req.extra_header_count && i < 4; i++) {
        const char *line = call->req.extra_headers != NULL
                               ? call->req.extra_headers[i]
                               : NULL;
        if (line != NULL) {
            snprintf(f->extra_headers[i], sizeof(f->extra_headers[i]), "%s",
                     line);
        }
    }
    f->has_query = call->req.query != NULL && call->req.query[0] != '\0';
    f->unsigned_payload = call->req.unsigned_payload;

    free(f->body);
    f->body = NULL;
    f->body_len = call->req.body_len;
    if (call->req.body != NULL && call->req.body_len > 0) {
        f->body = malloc(call->req.body_len + 1);
        if (f->body != NULL) {
            memcpy(f->body, call->req.body, call->req.body_len);
            f->body[call->req.body_len] = '\0';
        }
    }

    if (f->transport_rc != 0) {
        return f->transport_rc;
    }

    int idx = f->script_index;
    if (idx >= f->script_count) {
        idx = f->script_count > 0 ? f->script_count - 1 : 0;
    } else {
        f->script_index++;
    }
    long status = f->script_count > 0 ? f->script[idx].status : 200;
    const char *body = f->script_count > 0 ? f->script[idx].body : "{}";

    resp->status = status;
    if (body != NULL) {
        size_t len = strlen(body);
        resp->body = malloc(len + 1);
        if (resp->body != NULL) {
            memcpy(resp->body, body, len + 1);
            resp->body_len = len;
        }
    }
    return 0;
}

static ssm_client *make_client(fake_transport *f)
{
    ssm_client *client = NULL;
    int rc = ssm_client_init_with_transport(&client, NULL, "us-east-1",
                                            fake_send, f);
    CHECK_INT(rc, 0);
    return client;
}

/* --- JSON body helpers -------------------------------------------------- */

static yyjson_doc *parse_body(const fake_transport *f)
{
    if (f->body == NULL) {
        return NULL;
    }
    return yyjson_read(f->body, f->body_len, 0);
}

static const char *body_str(const fake_transport *f, const char *key)
{
    yyjson_doc *doc = parse_body(f);
    if (doc == NULL) {
        return NULL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *v = yyjson_obj_get(root, key);
    const char *s = (v != NULL && yyjson_is_str(v)) ? yyjson_get_str(v) : NULL;
    /* Caller must not retain this pointer across yyjson_doc_free; tests only
     * compare immediately, so return a static copy holder. */
    static char copy[SSM_PARAM_NAME_MAX];
    copy[0] = '\0';
    if (s != NULL) {
        snprintf(copy, sizeof(copy), "%s", s);
    }
    yyjson_doc_free(doc);
    return copy;
}

/* --- assertions for the shared request shape --------------------------- */

static void check_request_shape(const fake_transport *f, const char *target)
{
    CHECK_INT(f->calls, 1);
    CHECK_STR(f->method, "POST");
    CHECK_STR(f->path, "/");
    CHECK_STR(f->service, "ssm");
    CHECK_STR(f->region, "us-east-1");
    CHECK_STR(f->content_type, "");
    CHECK_STR(f->target, target);
    CHECK_INT(f->has_query, 0);
    CHECK_INT(f->unsigned_payload, 0);

    /* Every SSM JSON call carries a signed X-Amz-Target + Content-Type. */
    CHECK_INT(f->extra_header_count, SSM_EXTRA_HEADER_COUNT);
    char expected_target[SSM_TARGET_HEADER_MAX];
    snprintf(expected_target, sizeof(expected_target), "X-Amz-Target: %s",
             target);
    CHECK_STR(f->extra_headers[0], expected_target);
    CHECK_STR(f->extra_headers[1],
              "Content-Type: " SSM_API_CONTENT_TYPE);

    CHECK(f->body != NULL);
}

/* --- Parameter Store ---------------------------------------------------- */

static void test_get_parameter_request_and_parse(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200,
               "{\"Parameter\":{\"Name\":\"/demo/ddns/password\","
               "\"Type\":\"SecureString\",\"Value\":\"s3cret\",\"Version\":7,"
               "\"LastModifiedDate\":\"2026-01-02T03:04:05.678Z\","
               "\"ARN\":\"arn:aws:ssm:us-east-1:123:parameter/demo/ddns/password\","
               "\"DataType\":\"text\"}}");
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    int rc = ssm_get_parameter(client, "/demo/ddns/password", 1, &p);
    CHECK_INT(rc, 0);
    check_request_shape(&f, "AmazonSSM.GetParameter");
    CHECK_STR(body_str(&f, "Name"), "/demo/ddns/password");

    /* WithDecryption must be a JSON true. */
    yyjson_doc *doc = parse_body(&f);
    CHECK(doc != NULL);
    if (doc != NULL) {
        yyjson_val *wd =
            yyjson_obj_get(yyjson_doc_get_root(doc), "WithDecryption");
        CHECK(yyjson_is_true(wd));
        yyjson_doc_free(doc);
    }

    CHECK_STR(p.name, "/demo/ddns/password");
    CHECK_STR(p.type, "SecureString");
    CHECK_STR(p.value, "s3cret");
    CHECK_INT(p.version, 7);
    CHECK_STR(p.last_modified, "2026-01-02T03:04:05.678Z");
    CHECK_STR(p.arn,
              "arn:aws:ssm:us-east-1:123:parameter/demo/ddns/password");
    CHECK_STR(p.data_type, "text");

    ssm_parameter_free(&p);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_parameter_without_decryption(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200,
               "{\"Parameter\":{\"Name\":\"/demo/ami\",\"Type\":\"String\","
               "\"Value\":\"ami-123\"}}");
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    int rc = ssm_get_parameter(client, "/demo/ami", 0, &p);
    CHECK_INT(rc, 0);
    CHECK_STR(p.value, "ami-123");
    CHECK_INT(p.version, 0);
    CHECK_STR(p.type, "String");
    CHECK_STR(p.last_modified, "");

    yyjson_doc *doc = parse_body(&f);
    CHECK(doc != NULL);
    if (doc != NULL) {
        yyjson_val *wd =
            yyjson_obj_get(yyjson_doc_get_root(doc), "WithDecryption");
        CHECK(yyjson_is_false(wd));
        yyjson_doc_free(doc);
    }

    ssm_parameter_free(&p);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_parameter_not_found(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 400,
               "{\"__type\":\"ParameterNotFound\",\"message\":\"not here\"}");
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    int rc = ssm_get_parameter(client, "/demo/missing", 1, &p);
    CHECK_INT(rc, ENOENT);
    CHECK(p.name == NULL);
    CHECK(p.value == NULL);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_parameter_access_denied(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 400, "{\"__type\":\"AccessDeniedException\"}");
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    int rc = ssm_get_parameter(client, "/demo/secret", 1, &p);
    CHECK_INT(rc, EACCES);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_parameter_invalid_response(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, "{}");
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    int rc = ssm_get_parameter(client, "/demo/x", 1, &p);
    CHECK_INT(rc, EBADMSG);

    fake_reply(&f, 200, "not json");
    rc = ssm_get_parameter(client, "/demo/x", 1, &p);
    CHECK_INT(rc, EBADMSG);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_parameter_invalid_args(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    CHECK_INT(ssm_get_parameter(NULL, "/x", 1, &p), EINVAL);
    CHECK_INT(ssm_get_parameter(client, NULL, 1, &p), EINVAL);
    CHECK_INT(ssm_get_parameter(client, "", 1, &p), EINVAL);
    CHECK_INT(ssm_get_parameter(client, "no-slash", 1, &p), EINVAL);
    CHECK_INT(ssm_get_parameter(client, "/x", 1, NULL), EINVAL);
    CHECK_INT(f.calls, 0);

    ssm_client_free(client);
    fake_reset(&f);
}

/* --- SendCommand -------------------------------------------------------- */

static void test_send_command_request_and_parse(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, "{\"Command\":{\"CommandId\":\"cmd-abc\"}}");
    ssm_client *client = make_client(&f);

    const char *commands[] = {"echo one", "systemctl start app"};
    const char *instances[] = {"i-0123456789abcdef0"};
    ssm_send_spec spec = {
        .document_name = NULL,
        .commands = commands,
        .command_count = 2,
        .instance_ids = instances,
        .instance_id_count = 1,
        .timeout_seconds = 45,
        .comment = "hello",
    };
    ssm_send_result result;
    memset(&result, 0, sizeof(result));

    int rc = ssm_send_command(client, &spec, &result);
    CHECK_INT(rc, 0);
    check_request_shape(&f, "AmazonSSM.SendCommand");
    CHECK_STR(result.command_id, "cmd-abc");

    yyjson_doc *doc = parse_body(&f);
    CHECK(doc != NULL);
    if (doc != NULL) {
        yyjson_val *root = yyjson_doc_get_root(doc);
        CHECK_STR(yyjson_get_str(yyjson_obj_get(root, "DocumentName")),
                  SSM_DOCUMENT_RUN_SHELL_SCRIPT);
        yyjson_val *ids = yyjson_obj_get(root, "InstanceIds");
        CHECK(yyjson_is_arr(ids));
        CHECK_INT(yyjson_arr_size(ids), 1);
        CHECK_STR(yyjson_get_str(yyjson_arr_get(ids, 0)),
                  "i-0123456789abcdef0");
        yyjson_val *params = yyjson_obj_get(root, "Parameters");
        CHECK(yyjson_is_obj(params));
        yyjson_val *cmds = yyjson_obj_get(params, "commands");
        CHECK(yyjson_is_arr(cmds));
        CHECK_INT(yyjson_arr_size(cmds), 2);
        CHECK_STR(yyjson_get_str(yyjson_arr_get(cmds, 0)), "echo one");
        CHECK_STR(yyjson_get_str(yyjson_arr_get(cmds, 1)),
                  "systemctl start app");
        CHECK_INT(yyjson_get_int(yyjson_obj_get(root, "TimeoutSeconds")), 45);
        CHECK_STR(yyjson_get_str(yyjson_obj_get(root, "Comment")), "hello");
        yyjson_doc_free(doc);
    }

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_send_command_custom_document_and_omits_optional(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, "{\"Command\":{\"CommandId\":\"cmd-1\"}}");
    ssm_client *client = make_client(&f);

    const char *commands[] = {"true"};
    const char *instances[] = {"i-1"};
    ssm_send_spec spec = {
        .document_name = "AWS-RunPowerShellScript",
        .commands = commands,
        .command_count = 1,
        .instance_ids = instances,
        .instance_id_count = 1,
        .timeout_seconds = 0,
        .comment = NULL,
    };
    ssm_send_result result;
    memset(&result, 0, sizeof(result));

    CHECK_INT(ssm_send_command(client, &spec, &result), 0);

    yyjson_doc *doc = parse_body(&f);
    CHECK(doc != NULL);
    if (doc != NULL) {
        yyjson_val *root = yyjson_doc_get_root(doc);
        CHECK_STR(yyjson_get_str(yyjson_obj_get(root, "DocumentName")),
                  "AWS-RunPowerShellScript");
        CHECK(yyjson_obj_get(root, "TimeoutSeconds") == NULL);
        CHECK(yyjson_obj_get(root, "Comment") == NULL);
        yyjson_doc_free(doc);
    }

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_send_command_invalid_args(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    ssm_client *client = make_client(&f);

    const char *commands[] = {"true"};
    const char *empty_command[] = {""};
    const char *instances[] = {"i-1"};
    ssm_send_result result;
    memset(&result, 0, sizeof(result));

    ssm_send_spec no_commands = {
        .commands = NULL,
        .command_count = 0,
        .instance_ids = instances,
        .instance_id_count = 1,
    };
    ssm_send_spec no_instances = {
        .commands = commands,
        .command_count = 1,
        .instance_ids = NULL,
        .instance_id_count = 0,
    };
    ssm_send_spec blank_command = {
        .commands = empty_command,
        .command_count = 1,
        .instance_ids = instances,
        .instance_id_count = 1,
    };
    ssm_send_spec blank_instance = {
        .commands = commands,
        .command_count = 1,
        .instance_ids = (const char *const *)empty_command,
        .instance_id_count = 1,
    };

    CHECK_INT(ssm_send_command(client, NULL, &result), EINVAL);
    CHECK_INT(ssm_send_command(client, &no_commands, &result), EINVAL);
    CHECK_INT(ssm_send_command(client, &no_instances, &result), EINVAL);
    CHECK_INT(ssm_send_command(client, &blank_command, &result), EINVAL);
    CHECK_INT(ssm_send_command(client, &blank_instance, &result), EINVAL);
    CHECK_INT(ssm_send_command(client, &no_commands, NULL), EINVAL);
    CHECK_INT(f.calls, 0);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_send_command_missing_id(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, "{\"Command\":{}}");
    ssm_client *client = make_client(&f);

    const char *commands[] = {"true"};
    const char *instances[] = {"i-1"};
    ssm_send_spec spec = {
        .commands = commands,
        .command_count = 1,
        .instance_ids = instances,
        .instance_id_count = 1,
    };
    ssm_send_result result;
    memset(&result, 0, sizeof(result));

    CHECK_INT(ssm_send_command(client, &spec, &result), EBADMSG);
    CHECK_STR(result.command_id, "");

    ssm_client_free(client);
    fake_reset(&f);
}

/* --- GetCommandInvocation ---------------------------------------------- */

static const char *invocation_success =
    "{\"CommandId\":\"cmd-abc\",\"InstanceId\":\"i-1\",\"Status\":\"Success\","
    "\"StatusDetails\":\"Success\",\"ResponseCode\":0,"
    "\"StandardOutputContent\":\"hello out\\n\","
    "\"StandardErrorContent\":\"warn\\n\"}";

static void test_get_command_invocation_request_and_parse(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, invocation_success);
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));

    int rc = ssm_get_command_invocation(client, "cmd-abc", "i-1", &inv);
    CHECK_INT(rc, 0);
    check_request_shape(&f, "AmazonSSM.GetCommandInvocation");
    CHECK_STR(body_str(&f, "CommandId"), "cmd-abc");
    CHECK_STR(body_str(&f, "InstanceId"), "i-1");

    CHECK_STR(inv.command_id, "cmd-abc");
    CHECK_STR(inv.instance_id, "i-1");
    CHECK_STR(inv.status, "Success");
    CHECK_INT(inv.state, SSM_COMMAND_SUCCESS);
    CHECK_STR(inv.status_details, "Success");
    CHECK_STR(inv.standard_output, "hello out\n");
    CHECK_STR(inv.standard_error, "warn\n");
    CHECK_INT(inv.response_code, 0);

    ssm_invocation_free(&inv);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_command_invocation_not_found(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 400, "{\"__type\":\"InvocationDoesNotExist\"}");
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));

    CHECK_INT(ssm_get_command_invocation(client, "cmd", "i-1", &inv), ENOENT);
    CHECK(inv.standard_output == NULL);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_command_invocation_invalid_response(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, "{}");
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));

    CHECK_INT(ssm_get_command_invocation(client, "cmd", "i-1", &inv), EBADMSG);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_get_command_invocation_invalid_args(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));

    CHECK_INT(ssm_get_command_invocation(NULL, "c", "i", &inv), EINVAL);
    CHECK_INT(ssm_get_command_invocation(client, NULL, "i", &inv), EINVAL);
    CHECK_INT(ssm_get_command_invocation(client, "", "i", &inv), EINVAL);
    CHECK_INT(ssm_get_command_invocation(client, "c", NULL, &inv), EINVAL);
    CHECK_INT(ssm_get_command_invocation(client, "c", "", &inv), EINVAL);
    CHECK_INT(ssm_get_command_invocation(client, "c", "i", NULL), EINVAL);
    CHECK_INT(f.calls, 0);

    ssm_client_free(client);
    fake_reset(&f);
}

/* --- status mapping ----------------------------------------------------- */

static void test_status_mapping(void)
{
    CHECK_INT(ssm_command_status_parse("Pending"), SSM_COMMAND_PENDING);
    CHECK_INT(ssm_command_status_parse("InProgress"), SSM_COMMAND_IN_PROGRESS);
    CHECK_INT(ssm_command_status_parse("Delayed"), SSM_COMMAND_DELAYED);
    CHECK_INT(ssm_command_status_parse("Success"), SSM_COMMAND_SUCCESS);
    CHECK_INT(ssm_command_status_parse("Cancelled"), SSM_COMMAND_CANCELLED);
    CHECK_INT(ssm_command_status_parse("TimedOut"), SSM_COMMAND_TIMED_OUT);
    CHECK_INT(ssm_command_status_parse("Failed"), SSM_COMMAND_FAILED);
    CHECK_INT(ssm_command_status_parse("Cancelling"), SSM_COMMAND_CANCELLING);
    CHECK_INT(ssm_command_status_parse("Nope"), SSM_COMMAND_UNKNOWN);
    CHECK_INT(ssm_command_status_parse(NULL), SSM_COMMAND_UNKNOWN);

    CHECK_STR(ssm_command_status_name(SSM_COMMAND_PENDING), "Pending");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_IN_PROGRESS), "InProgress");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_DELAYED), "Delayed");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_SUCCESS), "Success");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_CANCELLED), "Cancelled");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_TIMED_OUT), "TimedOut");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_FAILED), "Failed");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_CANCELLING), "Cancelling");
    CHECK_STR(ssm_command_status_name(SSM_COMMAND_UNKNOWN), "Unknown");
    CHECK_STR(ssm_command_status_name((ssm_command_status)99), "Unknown");

    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_SUCCESS), 1);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_CANCELLED), 1);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_TIMED_OUT), 1);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_FAILED), 1);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_PENDING), 0);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_IN_PROGRESS), 0);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_DELAYED), 0);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_CANCELLING), 0);
    CHECK_INT(ssm_command_status_terminal(SSM_COMMAND_UNKNOWN), 0);
}

static void test_status_to_errno(void)
{
    CHECK_INT(ssm_status_to_errno(200, NULL), 0);
    CHECK_INT(ssm_status_to_errno(204, ""), 0);
    CHECK_INT(ssm_status_to_errno(400, "ParameterNotFound"), ENOENT);
    CHECK_INT(ssm_status_to_errno(400, "ParameterVersionNotFound"), ENOENT);
    CHECK_INT(ssm_status_to_errno(400, "InvocationDoesNotExist"), ENOENT);
    CHECK_INT(ssm_status_to_errno(400, "AccessDeniedException"), EACCES);
    CHECK_INT(ssm_status_to_errno(500, "InternalServerError"), SSM_ERR_AWS_API);
    CHECK_INT(ssm_status_to_errno(400, NULL), SSM_ERR_AWS_API);
    CHECK_INT(ssm_status_to_errno(0, NULL), SSM_ERR_AWS_API);
}

/* --- waiter ------------------------------------------------------------- */

static const char *invocation_pending =
    "{\"CommandId\":\"cmd\",\"InstanceId\":\"i-1\",\"Status\":\"Pending\","
    "\"StatusDetails\":\"Pending\"}";
static const char *invocation_running =
    "{\"CommandId\":\"cmd\",\"InstanceId\":\"i-1\",\"Status\":\"InProgress\","
    "\"StatusDetails\":\"InProgress\"}";
static const char *invocation_done =
    "{\"CommandId\":\"cmd\",\"InstanceId\":\"i-1\",\"Status\":\"Success\","
    "\"StatusDetails\":\"Success\",\"ResponseCode\":0,"
    "\"StandardOutputContent\":\"ok\"}";
static const char *invocation_failed =
    "{\"CommandId\":\"cmd\",\"InstanceId\":\"i-1\",\"Status\":\"Failed\","
    "\"StatusDetails\":\"Failed\",\"ResponseCode\":1,"
    "\"StandardErrorContent\":\"boom\"}";

static void test_wait_command_eventually_succeeds(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_queue(&f, 400, "{\"__type\":\"InvocationDoesNotExist\"}");
    fake_queue(&f, 200, invocation_running);
    fake_queue(&f, 200, invocation_done);
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));
    int timed_out = -1;

    int rc = ssm_wait_command(client, "cmd", "i-1", 5, 0, &inv, &timed_out);
    CHECK_INT(rc, 0);
    CHECK_INT(timed_out, 0);
    CHECK_INT(f.calls, 3);
    CHECK_INT(inv.state, SSM_COMMAND_SUCCESS);
    CHECK_STR(inv.standard_output, "ok");

    ssm_invocation_free(&inv);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_wait_command_terminal_failure(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, invocation_failed);
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));
    int timed_out = -1;

    int rc = ssm_wait_command(client, "cmd", "i-1", 5, 0, &inv, &timed_out);
    CHECK_INT(rc, 0);
    CHECK_INT(timed_out, 0);
    CHECK_INT(f.calls, 1);
    CHECK_INT(inv.state, SSM_COMMAND_FAILED);
    CHECK_STR(inv.standard_error, "boom");
    CHECK_INT(inv.response_code, 1);

    ssm_invocation_free(&inv);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_wait_command_times_out(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 200, invocation_pending);
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));
    int timed_out = -1;

    int rc = ssm_wait_command(client, "cmd", "i-1", 3, 0, &inv, &timed_out);
    CHECK_INT(rc, 0);
    CHECK_INT(timed_out, 1);
    CHECK_INT(f.calls, 3);
    CHECK_INT(inv.state, SSM_COMMAND_PENDING);

    ssm_invocation_free(&inv);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_wait_command_propagates_error(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    fake_reply(&f, 500, "{\"__type\":\"InternalServerError\"}");
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));
    int timed_out = -1;

    int rc = ssm_wait_command(client, "cmd", "i-1", 5, 0, &inv, &timed_out);
    CHECK_INT(rc, SSM_ERR_AWS_API);
    CHECK_INT(f.calls, 1);
    CHECK(inv.standard_output == NULL);

    ssm_invocation_free(&inv);
    ssm_client_free(client);
    fake_reset(&f);
}

static void test_wait_command_invalid_args(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    ssm_client *client = make_client(&f);
    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));
    int timed_out = 0;

    CHECK_INT(ssm_wait_command(NULL, "c", "i", 1, 0, &inv, &timed_out),
              EINVAL);
    CHECK_INT(ssm_wait_command(client, NULL, "i", 1, 0, &inv, &timed_out),
              EINVAL);
    CHECK_INT(ssm_wait_command(client, "c", "i", 0, 0, &inv, &timed_out),
              EINVAL);
    CHECK_INT(ssm_wait_command(client, "c", "i", 1, 0, &inv, NULL), EINVAL);
    CHECK_INT(f.calls, 0);

    ssm_client_free(client);
    fake_reset(&f);
}

/* --- client / helpers --------------------------------------------------- */

static void test_client_init_and_free(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    ssm_client *client = NULL;

    CHECK_INT(ssm_client_init_with_transport(&client, NULL, NULL, fake_send,
                                             &f),
              EINVAL);
    CHECK(client == NULL);
    CHECK_INT(ssm_client_init_with_transport(&client, NULL, "", fake_send, &f),
              EINVAL);
    CHECK_INT(ssm_client_init_with_transport(&client, NULL, "us-east-1", NULL,
                                             &f),
              EINVAL);
    CHECK_INT(ssm_client_init_with_transport(NULL, NULL, "us-east-1", fake_send,
                                             &f),
              EINVAL);

    CHECK_INT(ssm_client_init_with_transport(&client, NULL, "us-east-1",
                                             fake_send, &f),
              0);
    CHECK(client != NULL);
    ssm_client_free(client);
    ssm_client_free(NULL);

    /* Production constructor requires an initialized aws_ctx. */
    ssm_client *production = NULL;
    CHECK_INT(ssm_client_init(&production, NULL, "us-east-1"), EINVAL);
    CHECK(production == NULL);
}

static void test_build_target(void)
{
    char out[64];

    CHECK_INT(ssm_build_target("GetParameter", out, sizeof(out)), 0);
    CHECK_STR(out, "AmazonSSM.GetParameter");

    CHECK_INT(ssm_build_target(NULL, out, sizeof(out)), EINVAL);
    CHECK_INT(ssm_build_target("", out, sizeof(out)), EINVAL);
    CHECK_INT(ssm_build_target("X", out, 5), EFBIG);
    CHECK_INT(ssm_build_target("X", NULL, 10), EINVAL);
}

/* Production seam: the two signed extra header lines for an SSM operation. */
static void test_build_headers(void)
{
    char target_header[SSM_TARGET_HEADER_MAX];
    const char *headers[SSM_EXTRA_HEADER_COUNT] = {NULL, NULL};

    CHECK_INT(ssm_build_headers("GetParameter", target_header,
                                sizeof(target_header), headers),
              0);
    CHECK_STR(headers[0], "X-Amz-Target: AmazonSSM.GetParameter");
    CHECK_STR(headers[1], "Content-Type: application/x-amz-json-1.1");
    CHECK(headers[0] == target_header);

    CHECK_INT(ssm_build_headers("SendCommand", target_header,
                                sizeof(target_header), headers),
              0);
    CHECK_STR(headers[0], "X-Amz-Target: AmazonSSM.SendCommand");

    CHECK_INT(ssm_build_headers(NULL, target_header, sizeof(target_header),
                                headers),
              EINVAL);
    CHECK_INT(ssm_build_headers("", target_header, sizeof(target_header),
                                headers),
              EINVAL);
    CHECK_INT(ssm_build_headers("GetParameter", NULL,
                                sizeof(target_header), headers),
              EINVAL);
    CHECK_INT(ssm_build_headers("GetParameter", target_header,
                                sizeof(target_header), NULL),
              EINVAL);
    /* "X-Amz-Target: " is 14 bytes plus the 10-char prefix and Operation. */
    CHECK_INT(ssm_build_headers("GetParameter", target_header, 20, headers),
              EFBIG);
}

static void test_transport_error_propagates(void)
{
    fake_transport f;
    memset(&f, 0, sizeof(f));
    f.transport_rc = ECONNRESET;
    ssm_client *client = make_client(&f);
    ssm_parameter p;
    memset(&p, 0, sizeof(p));

    CHECK_INT(ssm_get_parameter(client, "/demo/x", 1, &p), ECONNRESET);

    ssm_client_free(client);
    fake_reset(&f);
}

static void test_free_null_safe(void)
{
    ssm_parameter p;
    memset(&p, 0, sizeof(p));
    ssm_parameter_free(&p);
    ssm_parameter_free(NULL);

    ssm_invocation inv;
    memset(&inv, 0, sizeof(inv));
    ssm_invocation_free(&inv);
    ssm_invocation_free(NULL);
}

int main(void)
{
    test_get_parameter_request_and_parse();
    test_get_parameter_without_decryption();
    test_get_parameter_not_found();
    test_get_parameter_access_denied();
    test_get_parameter_invalid_response();
    test_get_parameter_invalid_args();
    test_send_command_request_and_parse();
    test_send_command_custom_document_and_omits_optional();
    test_send_command_invalid_args();
    test_send_command_missing_id();
    test_get_command_invocation_request_and_parse();
    test_get_command_invocation_not_found();
    test_get_command_invocation_invalid_response();
    test_get_command_invocation_invalid_args();
    test_status_mapping();
    test_status_to_errno();
    test_wait_command_eventually_succeeds();
    test_wait_command_terminal_failure();
    test_wait_command_times_out();
    test_wait_command_propagates_error();
    test_wait_command_invalid_args();
    test_client_init_and_free();
    test_build_target();
    test_build_headers();
    test_transport_error_propagates();
    test_free_null_safe();

    if (failures != 0) {
        fprintf(stderr, "%d/%d checks failed\n", failures, checks);
        return 1;
    }
    printf("all %d checks passed\n", checks);
    return 0;
}
