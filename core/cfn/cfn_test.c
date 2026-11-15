/*
 * cfn_test.c — request-shape and response-parsing tests for core/cfn.
 *
 * A fake transport captures every aws_req (action/version/service/region/
 * content type/body) and serves fixture XML, so no credentials or network are
 * involved. Each public operation and both waiters are exercised, including
 * AWS error mapping, pagination and idempotent deletes.
 */

#include "cfn.h"
#include "cfn_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define MAX_CALLS 16

typedef struct fake_call {
    char method[16];
    char service[64];
    char region[64];
    char path[128];
    char content_type[160];
    char *body;
} fake_call;

typedef struct fake {
    fake_call calls[MAX_CALLS];
    int count;
    const char *responses[MAX_CALLS];
    long statuses[MAX_CALLS];
    int response_count;
    int response_index;
} fake;

static void fake_clear(fake *f)
{
    for (int i = 0; i < f->count && i < MAX_CALLS; i++) {
        free(f->calls[i].body);
        f->calls[i].body = NULL;
    }
    f->count = 0;
    f->response_count = 0;
    f->response_index = 0;
}

static void fake_serve(fake *f, const char *body)
{
    f->responses[f->response_count] = body;
    f->statuses[f->response_count] = 200;
    f->response_count++;
}

static void fake_serve_status(fake *f, long status, const char *body)
{
    f->responses[f->response_count] = body;
    f->statuses[f->response_count] = status;
    f->response_count++;
}

static int fake_send(aws_ctx *ctx, const aws_req *req, aws_resp *resp, void *ud)
{
    (void)ctx;
    fake *f = ud;
    if (f->count >= MAX_CALLS) {
        return EOVERFLOW;
    }
    fake_call *call = &f->calls[f->count++];
    snprintf(call->method, sizeof(call->method), "%s", req->method);
    snprintf(call->service, sizeof(call->service), "%s", req->service);
    snprintf(call->region, sizeof(call->region), "%s", req->region);
    snprintf(call->path, sizeof(call->path), "%s", req->path);
    snprintf(call->content_type, sizeof(call->content_type), "%s",
             req->content_type != NULL ? req->content_type : "");
    if (req->body != NULL) {
        call->body = malloc(req->body_len + 1);
        if (call->body == NULL) {
            return ENOMEM;
        }
        memcpy(call->body, req->body, req->body_len);
        call->body[req->body_len] = '\0';
    }

    int idx = f->response_index;
    if (idx >= f->response_count) {
        idx = f->response_count - 1;
    }
    if (idx < 0) {
        return EIO;
    }
    f->response_index++;

    memset(resp, 0, sizeof(*resp));
    resp->status = f->statuses[idx];
    const char *body = f->responses[idx] != NULL ? f->responses[idx] : "";
    resp->body = strdup(body);
    if (resp->body == NULL) {
        return ENOMEM;
    }
    resp->body_len = strlen(body);
    return 0;
}

static fake_call *last_call(fake *f)
{
    return f->count > 0 ? &f->calls[f->count - 1] : NULL;
}

static void expect_body(fake *f, const char *expected)
{
    fake_call *call = last_call(f);
    if (call == NULL || call->body == NULL ||
        strcmp(call->body, expected) != 0) {
        fprintf(stderr, "FAIL body mismatch\n  expected: %s\n  actual:   %s\n",
                expected, call != NULL && call->body != NULL ? call->body : "(none)");
        failures++;
    }
}

static void expect_common(fake *f, const char *region)
{
    fake_call *call = last_call(f);
    CHECK(call != NULL, "a request was sent");
    if (call == NULL) {
        return;
    }
    CHECK(strcmp(call->method, "POST") == 0, "method POST");
    CHECK(strcmp(call->service, "cloudformation") == 0, "service cloudformation");
    CHECK(strcmp(call->region, region) == 0, "region propagated");
    CHECK(strcmp(call->path, "/") == 0, "path /");
    CHECK(strcmp(call->content_type,
                 "application/x-www-form-urlencoded; charset=utf-8") == 0,
          "form content type");
}

static cfn_client *make_client(fake *f)
{
    cfn_client *client = NULL;
    int rc = cfn_client_create_with_transport(&client, NULL, fake_send, f);
    CHECK(rc == 0, "fake client created");
    return client;
}

/* ------------------------------------------------------------- fixtures */

static const char *STACK_XML =
    "<DescribeStacksResponse xmlns=\"http://cloudformation.amazonaws.com/doc/2010-05-15/\">"
    "<DescribeStacksResult><Stacks><member>"
    "<StackId>arn:aws:cloudformation:us-east-1:123:stack/proj-infra/abc</StackId>"
    "<StackName>proj-infra</StackName>"
    "<StackStatus>UPDATE_COMPLETE</StackStatus>"
    "<StackStatusReason>done &amp; dusted</StackStatusReason>"
    "<Parameters><member><ParameterKey>ReleaseTag</ParameterKey>"
    "<ParameterValue>v1.2.3</ParameterValue></member>"
    "<member><ParameterKey>AmiIdAmd64</ParameterKey>"
    "<ParameterValue>ami-123</ParameterValue></member></Parameters>"
    "<Outputs><member><OutputKey>VpcId</OutputKey><OutputValue>vpc-1</OutputValue>"
    "<Description>the vpc</Description></member></Outputs>"
    "<Tags><member><Key>stackctl:release-tag</Key><Value>v1.2.3</Value></member>"
    "</Tags>"
    "</member></Stacks></DescribeStacksResult>"
    "<ResponseMetadata><RequestId>x</RequestId></ResponseMetadata>"
    "</DescribeStacksResponse>";

static const char *STACK_PAGE_ONE =
    "<DescribeStacksResponse><DescribeStacksResult><Stacks><member>"
    "<StackName>one</StackName><StackStatus>CREATE_COMPLETE</StackStatus>"
    "</member></Stacks><NextToken>tok</NextToken></DescribeStacksResult>"
    "</DescribeStacksResponse>";

static const char *STACK_PAGE_TWO =
    "<DescribeStacksResponse><DescribeStacksResult><Stacks><member>"
    "<StackName>two</StackName><StackStatus>CREATE_FAILED</StackStatus>"
    "</member></Stacks></DescribeStacksResult></DescribeStacksResponse>";

static const char *CHANGE_SET_RESULT_XML =
    "<CreateChangeSetResponse><CreateChangeSetResult>"
    "<Id>arn:aws:cloudformation:us-east-1:123:changeSet/cs/1</Id>"
    "<StackId>arn:aws:cloudformation:us-east-1:123:stack/proj-infra/abc</StackId>"
    "</CreateChangeSetResult></CreateChangeSetResponse>";

static const char *CHANGE_SET_PAGE_ONE =
    "<DescribeChangeSetResponse><DescribeChangeSetResult>"
    "<ChangeSetId>id-1</ChangeSetId><ChangeSetName>cs1</ChangeSetName>"
    "<StackId>stack-id</StackId><StackName>proj-infra</StackName>"
    "<Status>CREATE_COMPLETE</Status><ExecutionStatus>AVAILABLE</ExecutionStatus>"
    "<Changes><member><Type>Resource</Type><ResourceChange>"
    "<Action>Modify</Action><LogicalResourceId>Vpc</LogicalResourceId>"
    "<PhysicalResourceId>vpc-1</PhysicalResourceId>"
    "<ResourceType>AWS::EC2::VPC</ResourceType><Replacement>False</Replacement>"
    "</ResourceChange></member></Changes><NextToken>tok</NextToken>"
    "</DescribeChangeSetResult></DescribeChangeSetResponse>";

static const char *CHANGE_SET_PAGE_TWO =
    "<DescribeChangeSetResponse><DescribeChangeSetResult>"
    "<Changes><member><Type>Resource</Type><ResourceChange>"
    "<Action>Add</Action><LogicalResourceId>Bucket</LogicalResourceId>"
    "<ResourceType>AWS::S3::Bucket</ResourceType><Replacement>True</Replacement>"
    "</ResourceChange></member></Changes>"
    "</DescribeChangeSetResult></DescribeChangeSetResponse>";

static const char *CHANGE_SET_EMPTY =
    "<DescribeChangeSetResponse><DescribeChangeSetResult>"
    "<ChangeSetId>id-2</ChangeSetId><Status>CREATE_COMPLETE</Status>"
    "<ExecutionStatus>AVAILABLE</ExecutionStatus>"
    "</DescribeChangeSetResult></DescribeChangeSetResponse>";

static const char *SUMMARY_XML =
    "<GetTemplateSummaryResponse><GetTemplateSummaryResult>"
    "<Description>infra template</Description>"
    "<Parameters><member><ParameterKey>ProjectName</ParameterKey>"
    "<DefaultValue>proj</DefaultValue><ParameterType>String</ParameterType>"
    "<Description>project</Description><NoEcho>false</NoEcho></member>"
    "<member><ParameterKey>Secret</ParameterKey><ParameterType>String</ParameterType>"
    "<NoEcho>true</NoEcho></member></Parameters>"
    "<Capabilities><member>CAPABILITY_NAMED_IAM</member></Capabilities>"
    "<ResourceTypes><member>AWS::EC2::VPC</member>"
    "<member>AWS::S3::Bucket</member></ResourceTypes>"
    "</GetTemplateSummaryResult></GetTemplateSummaryResponse>";

static const char *RESOURCES_XML =
    "<DescribeStackResourcesResponse><DescribeStackResourcesResult>"
    "<StackResources><member><LogicalResourceId>Vpc</LogicalResourceId>"
    "<PhysicalResourceId>vpc-1</PhysicalResourceId>"
    "<ResourceType>AWS::EC2::VPC</ResourceType>"
    "<ResourceStatus>CREATE_COMPLETE</ResourceStatus></member>"
    "</StackResources></DescribeStackResourcesResult>"
    "</DescribeStackResourcesResponse>";

static const char *EVENTS_XML =
    "<DescribeStackEventsResponse><DescribeStackEventsResult>"
    "<StackEvents><member><EventId>e1</EventId>"
    "<Timestamp>2026-01-01T00:00:00.000Z</Timestamp>"
    "<LogicalResourceId>proj-infra</LogicalResourceId>"
    "<PhysicalResourceId>arn:stack</PhysicalResourceId>"
    "<ResourceType>AWS::CloudFormation::Stack</ResourceType>"
    "<ResourceStatus>CREATE_COMPLETE</ResourceStatus>"
    "<ResourceStatusReason>ok</ResourceStatusReason></member>"
    "</StackEvents></DescribeStackEventsResult></DescribeStackEventsResponse>";

static const char *ERROR_NOT_FOUND =
    "<ErrorResponse><Error><Type>Sender</Type><Code>ValidationError</Code>"
    "<Message>Stack with id proj-infra does not exist</Message></Error>"
    "<RequestId>r</RequestId></ErrorResponse>";

static const char *ERROR_ACCESS =
    "<ErrorResponse><Error><Code>AccessDenied</Code>"
    "<Message>not allowed</Message></Error></ErrorResponse>";

static const char *ERROR_CAPS =
    "<ErrorResponse><Error><Code>InsufficientCapabilitiesException</Code>"
    "<Message>Requires capabilities</Message></Error></ErrorResponse>";

static const char *ERROR_NO_UPDATES =
    "<ErrorResponse><Error><Code>ValidationError</Code>"
    "<Message>No updates are to be performed.</Message></Error></ErrorResponse>";

static const char *ERROR_EXISTS =
    "<ErrorResponse><Error><Code>AlreadyExistsException</Code>"
    "<Message>Stack already exists</Message></Error></ErrorResponse>";

static const char *ERROR_GENERIC =
    "<ErrorResponse><Error><Code>InternalFailure</Code>"
    "<Message>boom</Message></Error></ErrorResponse>";

static char *status_xml(const char *status, const char *reason)
{
    static char buffers[4][1024];
    static unsigned int next;
    char *buffer = buffers[next++ % 4];
    snprintf(buffer, sizeof(buffers[0]),
             "<DescribeStacksResponse><DescribeStacksResult><Stacks><member>"
             "<StackName>proj-infra</StackName><StackStatus>%s</StackStatus>"
             "<StackStatusReason>%s</StackStatusReason>"
             "</member></Stacks></DescribeStacksResult></DescribeStacksResponse>",
             status, reason != NULL ? reason : "");
    return buffer;
}

/* ------------------------------------------------------------------ tests */

static void test_client(void)
{
    cfn_client *client = NULL;
    CHECK(cfn_client_create(&client, NULL) == EINVAL, "create rejects NULL aws");
    CHECK(cfn_client_create(NULL, NULL) == EINVAL, "create rejects NULL out");
    cfn_client_destroy(NULL);
}

static void test_status_mapping(void)
{
    static const struct {
        cfn_stack_status status;
        const char *name;
    } table[] = {
        {CFN_STACK_STATUS_CREATE_IN_PROGRESS, "CREATE_IN_PROGRESS"},
        {CFN_STACK_STATUS_CREATE_FAILED, "CREATE_FAILED"},
        {CFN_STACK_STATUS_CREATE_COMPLETE, "CREATE_COMPLETE"},
        {CFN_STACK_STATUS_ROLLBACK_IN_PROGRESS, "ROLLBACK_IN_PROGRESS"},
        {CFN_STACK_STATUS_ROLLBACK_FAILED, "ROLLBACK_FAILED"},
        {CFN_STACK_STATUS_ROLLBACK_COMPLETE, "ROLLBACK_COMPLETE"},
        {CFN_STACK_STATUS_DELETE_IN_PROGRESS, "DELETE_IN_PROGRESS"},
        {CFN_STACK_STATUS_DELETE_FAILED, "DELETE_FAILED"},
        {CFN_STACK_STATUS_DELETE_COMPLETE, "DELETE_COMPLETE"},
        {CFN_STACK_STATUS_UPDATE_IN_PROGRESS, "UPDATE_IN_PROGRESS"},
        {CFN_STACK_STATUS_UPDATE_COMPLETE_CLEANUP_IN_PROGRESS,
         "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"},
        {CFN_STACK_STATUS_UPDATE_COMPLETE, "UPDATE_COMPLETE"},
        {CFN_STACK_STATUS_UPDATE_FAILED, "UPDATE_FAILED"},
        {CFN_STACK_STATUS_UPDATE_ROLLBACK_IN_PROGRESS,
         "UPDATE_ROLLBACK_IN_PROGRESS"},
        {CFN_STACK_STATUS_UPDATE_ROLLBACK_FAILED, "UPDATE_ROLLBACK_FAILED"},
        {CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS,
         "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS"},
        {CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE, "UPDATE_ROLLBACK_COMPLETE"},
        {CFN_STACK_STATUS_REVIEW_IN_PROGRESS, "REVIEW_IN_PROGRESS"},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        cfn_stack_status parsed = CFN_STACK_STATUS_UNKNOWN;
        CHECK(strcmp(cfn_stack_status_string(table[i].status), table[i].name) == 0,
              "status string");
        CHECK(cfn_stack_status_parse(table[i].name, &parsed) == 0 &&
                  parsed == table[i].status,
              "status parse");
        int expect_in_progress =
            strstr(table[i].name, "_IN_PROGRESS") != NULL &&
            strcmp(table[i].name, "REVIEW_IN_PROGRESS") != 0;
        CHECK(cfn_stack_status_is_in_progress(table[i].status) ==
                  expect_in_progress,
              "in-progress classification");
    }
    CHECK(cfn_stack_status_is_healthy(CFN_STACK_STATUS_CREATE_COMPLETE), "healthy create");
    CHECK(cfn_stack_status_is_healthy(CFN_STACK_STATUS_UPDATE_COMPLETE), "healthy update");
    CHECK(cfn_stack_status_is_healthy(CFN_STACK_STATUS_UPDATE_ROLLBACK_COMPLETE),
          "healthy update rollback complete");
    CHECK(!cfn_stack_status_is_healthy(CFN_STACK_STATUS_ROLLBACK_COMPLETE),
          "rollback complete is not healthy");
    CHECK(!cfn_stack_status_is_in_progress(CFN_STACK_STATUS_REVIEW_IN_PROGRESS),
          "review is not a running operation");

    cfn_stack_status unknown = CFN_STACK_STATUS_CREATE_COMPLETE;
    CHECK(cfn_stack_status_parse("SOMETHING_NEW", &unknown) == 0 &&
              unknown == CFN_STACK_STATUS_UNKNOWN,
          "unknown status tolerated");
    CHECK(cfn_stack_status_parse(NULL, &unknown) == EINVAL, "NULL status name");

    static const struct {
        cfn_change_set_status status;
        const char *name;
    } cs[] = {
        {CFN_CHANGE_SET_STATUS_CREATE_PENDING, "CREATE_PENDING"},
        {CFN_CHANGE_SET_STATUS_CREATE_IN_PROGRESS, "CREATE_IN_PROGRESS"},
        {CFN_CHANGE_SET_STATUS_CREATE_COMPLETE, "CREATE_COMPLETE"},
        {CFN_CHANGE_SET_STATUS_DELETE_COMPLETE, "DELETE_COMPLETE"},
        {CFN_CHANGE_SET_STATUS_FAILED, "FAILED"},
    };
    for (size_t i = 0; i < sizeof(cs) / sizeof(cs[0]); i++) {
        cfn_change_set_status parsed = CFN_CHANGE_SET_STATUS_UNKNOWN;
        CHECK(strcmp(cfn_change_set_status_string(cs[i].status), cs[i].name) == 0,
              "change-set status string");
        CHECK(cfn_change_set_status_parse(cs[i].name, &parsed) == 0 &&
                  parsed == cs[i].status,
              "change-set status parse");
    }

    static const struct {
        cfn_change_set_execution_status status;
        const char *name;
    } ex[] = {
        {CFN_CHANGE_SET_EXECUTION_UNAVAILABLE, "UNAVAILABLE"},
        {CFN_CHANGE_SET_EXECUTION_AVAILABLE, "AVAILABLE"},
        {CFN_CHANGE_SET_EXECUTION_IN_PROGRESS, "EXECUTE_IN_PROGRESS"},
        {CFN_CHANGE_SET_EXECUTION_COMPLETE, "EXECUTE_COMPLETE"},
        {CFN_CHANGE_SET_EXECUTION_FAILED, "EXECUTE_FAILED"},
        {CFN_CHANGE_SET_EXECUTION_OBSOLETE, "OBSOLETE"},
    };
    for (size_t i = 0; i < sizeof(ex) / sizeof(ex[0]); i++) {
        cfn_change_set_execution_status parsed = CFN_CHANGE_SET_EXECUTION_UNKNOWN;
        CHECK(strcmp(cfn_change_set_execution_status_string(ex[i].status),
                     ex[i].name) == 0,
              "execution status string");
        CHECK(cfn_change_set_execution_status_parse(ex[i].name, &parsed) == 0 &&
                  parsed == ex[i].status,
              "execution status parse");
    }
}

static void test_describe_stacks(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, STACK_XML);

    cfn_stack_list list = {0};
    int rc = cfn_describe_stacks(client, "us-east-1", "proj-infra", &list);
    CHECK(rc == 0, "describe_stacks ok");
    expect_common(&f, "us-east-1");
    expect_body(&f, "Action=DescribeStacks&Version=2010-05-15&StackName=proj-infra");
    CHECK(list.count == 1, "one stack");
    if (list.count == 1) {
        cfn_stack *s = &list.items[0];
        CHECK(strcmp(s->stack_name, "proj-infra") == 0, "stack name");
        CHECK(strcmp(s->stack_id,
                     "arn:aws:cloudformation:us-east-1:123:stack/proj-infra/abc") == 0,
              "stack id");
        CHECK(s->status == CFN_STACK_STATUS_UPDATE_COMPLETE, "stack status");
        CHECK(strcmp(s->status_reason, "done & dusted") == 0, "entity decoded");
        CHECK(s->parameter_count == 2, "parameters parsed");
        CHECK(strcmp(cfn_stack_parameter(s, "ReleaseTag"), "v1.2.3") == 0,
              "parameter lookup");
        CHECK(cfn_stack_parameter(s, "Missing") == NULL, "missing parameter");
        CHECK(s->output_count == 1, "outputs parsed");
        CHECK(strcmp(cfn_stack_output(s, "VpcId"), "vpc-1") == 0, "output lookup");
        CHECK(cfn_stack_output(s, "Nope") == NULL, "missing output");
        CHECK(s->tag_count == 1, "tags parsed");
        CHECK(strcmp(cfn_stack_tag(s, "stackctl:release-tag"), "v1.2.3") == 0,
              "tag lookup");
    }
    cfn_stack_list_free(&list);
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_describe_stacks_pagination(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, STACK_PAGE_ONE);
    fake_serve(&f, STACK_PAGE_TWO);

    cfn_stack_list list = {0};
    int rc = cfn_describe_stacks(client, "eu-west-1", NULL, &list);
    CHECK(rc == 0, "describe all stacks ok");
    CHECK(f.count == 2, "two pages fetched");
    expect_body(&f, "Action=DescribeStacks&Version=2010-05-15&NextToken=tok");
    CHECK(list.count == 2, "two stacks accumulated");
    if (list.count == 2) {
        CHECK(strcmp(list.items[0].stack_name, "one") == 0, "first page order");
        CHECK(list.items[1].status == CFN_STACK_STATUS_CREATE_FAILED, "second page status");
    }
    cfn_stack_list_free(&list);
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_create_change_set(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, CHANGE_SET_RESULT_XML);

    cfn_parameter params[2] = {0};
    snprintf(params[0].key, sizeof(params[0].key), "ReleaseTag");
    snprintf(params[0].value, sizeof(params[0].value), "v1.2.3");
    snprintf(params[1].key, sizeof(params[1].key), "AmiIdAmd64");
    params[1].use_previous_value = 1;
    cfn_tag tags[1] = {0};
    snprintf(tags[0].key, sizeof(tags[0].key), "stackctl:release-tag");
    snprintf(tags[0].value, sizeof(tags[0].value), "v1.2.3");

    cfn_change_set_spec spec = {
        .stack_name = "proj-infra",
        .change_set_name = "stackctl-20260101",
        .template_body = "{\"a\":\"b c\"}",
        .type = CFN_CHANGE_SET_TYPE_UPDATE,
        .parameters = params,
        .parameter_count = 2,
        .tags = tags,
        .tag_count = 1,
        .description = "deploy v1.2.3",
        .capabilities = CFN_CAPABILITY_NAMED_IAM | CFN_CAPABILITY_AUTO_EXPAND,
    };
    cfn_change_set_result result = {0};
    int rc = cfn_create_change_set(client, "us-east-1", &spec, &result);
    CHECK(rc == 0, "create_change_set ok");
    expect_common(&f, "us-east-1");
    expect_body(&f,
        "Action=CreateChangeSet&Version=2010-05-15&StackName=proj-infra"
        "&ChangeSetName=stackctl-20260101&ChangeSetType=UPDATE"
        "&TemplateBody=%7B%22a%22%3A%22b%20c%22%7D"
        "&Description=deploy%20v1.2.3"
        "&Capabilities.member.1=CAPABILITY_NAMED_IAM"
        "&Capabilities.member.2=CAPABILITY_AUTO_EXPAND"
        "&Parameters.member.1.ParameterKey=ReleaseTag"
        "&Parameters.member.1.ParameterValue=v1.2.3"
        "&Parameters.member.2.ParameterKey=AmiIdAmd64"
        "&Parameters.member.2.UsePreviousValue=true"
        "&Tags.member.1.Key=stackctl%3Arelease-tag"
        "&Tags.member.1.Value=v1.2.3");
    CHECK(strcmp(result.change_set_id,
                 "arn:aws:cloudformation:us-east-1:123:changeSet/cs/1") == 0,
          "change set id parsed");
    CHECK(strcmp(result.stack_id,
                 "arn:aws:cloudformation:us-east-1:123:stack/proj-infra/abc") == 0,
          "stack id parsed");

    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_create_change_set_validation(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    cfn_change_set_spec spec = {.stack_name = "s", .change_set_name = "c"};
    cfn_change_set_result result = {0};
    CHECK(cfn_create_change_set(client, "us-east-1", &spec, &result) == EINVAL,
          "missing template body rejected");
    spec.template_body = "{}";
    spec.type = CFN_CHANGE_SET_TYPE_CREATE;
    spec.change_set_name = "";
    CHECK(cfn_create_change_set(client, "us-east-1", &spec, &result) == EINVAL,
          "missing change set name rejected");
    CHECK(f.count == 0, "no request for invalid input");
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_describe_change_set(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, CHANGE_SET_PAGE_ONE);
    fake_serve(&f, CHANGE_SET_PAGE_TWO);

    cfn_change_set cs = {0};
    int rc = cfn_describe_change_set(client, "us-east-1", "proj-infra", "cs1", &cs);
    CHECK(rc == 0, "describe_change_set ok");
    CHECK(f.count == 2, "change set paginated");
    expect_body(&f,
        "Action=DescribeChangeSet&Version=2010-05-15&StackName=proj-infra"
        "&ChangeSetName=cs1&NextToken=tok");
    CHECK(cs.status == CFN_CHANGE_SET_STATUS_CREATE_COMPLETE, "status parsed");
    CHECK(cs.execution_status == CFN_CHANGE_SET_EXECUTION_AVAILABLE,
          "execution status parsed");
    CHECK(cs.change_count == 2, "changes accumulated across pages");
    if (cs.change_count == 2) {
        CHECK(strcmp(cs.changes[0].action, "Modify") == 0, "change action");
        CHECK(strcmp(cs.changes[0].logical_resource_id, "Vpc") == 0, "logical id");
        CHECK(strcmp(cs.changes[0].resource_type, "AWS::EC2::VPC") == 0, "type");
        CHECK(strcmp(cs.changes[1].action, "Add") == 0, "second change action");
        CHECK(strcmp(cs.changes[1].replacement, "True") == 0, "replacement");
    }
    cfn_change_set_free(&cs);
    CHECK(cs.changes == NULL && cs.change_count == 0, "free resets");

    fake_clear(&f);
    fake_serve(&f, CHANGE_SET_EMPTY);
    rc = cfn_describe_change_set(client, "us-east-1", "proj-infra", "cs2", &cs);
    CHECK(rc == 0 && cs.change_count == 0, "empty change set is not an error");
    cfn_change_set_free(&cs);
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_execute_and_delete_change_set(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, "<ExecuteChangeSetResponse/>");
    int rc = cfn_execute_change_set(client, "us-east-1", "proj-infra", "cs1");
    CHECK(rc == 0, "execute change set ok");
    expect_body(&f,
        "Action=ExecuteChangeSet&Version=2010-05-15&StackName=proj-infra"
        "&ChangeSetName=cs1");

    fake_clear(&f);
    fake_serve(&f, "<DeleteChangeSetResponse/>");
    rc = cfn_delete_change_set(client, "us-east-1", "proj-infra", "cs1");
    CHECK(rc == 0, "delete change set ok");
    expect_body(&f,
        "Action=DeleteChangeSet&Version=2010-05-15&StackName=proj-infra"
        "&ChangeSetName=cs1");

    fake_clear(&f);
    fake_serve_status(&f, 400, ERROR_NOT_FOUND);
    rc = cfn_delete_change_set(client, "us-east-1", "proj-infra", "cs1");
    CHECK(rc == 0, "delete of absent change set is idempotent");

    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_template_summary(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, SUMMARY_XML);

    cfn_template_summary summary = {0};
    int rc = cfn_get_template_summary(client, "us-east-1", "{\"x\":1}", &summary);
    CHECK(rc == 0, "get_template_summary ok");
    expect_body(&f,
        "Action=GetTemplateSummary&Version=2010-05-15"
        "&TemplateBody=%7B%22x%22%3A1%7D");
    CHECK(summary.parameter_count == 2, "summary parameters");
    if (summary.parameter_count == 2) {
        CHECK(strcmp(summary.parameters[0].key, "ProjectName") == 0, "param key");
        CHECK(strcmp(summary.parameters[0].default_value, "proj") == 0,
              "param default");
        CHECK(!summary.parameters[0].no_echo, "noecho false");
        CHECK(summary.parameters[1].no_echo, "noecho true");
    }
    CHECK(summary.capabilities.count == 1 &&
              strcmp(summary.capabilities.items[0], "CAPABILITY_NAMED_IAM") == 0,
          "capabilities parsed");
    CHECK(summary.resource_types.count == 2 &&
              strcmp(summary.resource_types.items[1], "AWS::S3::Bucket") == 0,
          "resource types parsed");
    CHECK(strcmp(summary.description, "infra template") == 0, "description");
    cfn_template_summary_free(&summary);
    CHECK(summary.parameters == NULL && summary.capabilities.count == 0,
          "summary free resets");
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_delete_stack(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, "<DeleteStackResponse/>");
    int rc = cfn_delete_stack(client, "us-east-1", "proj-infra");
    CHECK(rc == 0, "delete stack ok");
    expect_body(&f, "Action=DeleteStack&Version=2010-05-15&StackName=proj-infra");

    fake_clear(&f);
    fake_serve_status(&f, 400, ERROR_NOT_FOUND);
    CHECK(cfn_delete_stack(client, "us-east-1", "proj-infra") == 0,
          "delete absent stack is idempotent");
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_stack_resources(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, RESOURCES_XML);
    cfn_stack_resource_list list = {0};
    int rc = cfn_describe_stack_resources(client, "us-east-1", "proj-infra", &list);
    CHECK(rc == 0, "describe stack resources ok");
    expect_body(&f,
        "Action=DescribeStackResources&Version=2010-05-15"
        "&StackName=proj-infra");
    CHECK(list.count == 1, "one resource");
    if (list.count == 1) {
        CHECK(strcmp(list.items[0].logical_resource_id, "Vpc") == 0, "resource logical id");
        CHECK(strcmp(list.items[0].resource_type, "AWS::EC2::VPC") == 0,
              "resource type");
    }
    cfn_stack_resource_list_free(&list);
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_stack_events(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, EVENTS_XML);
    cfn_event_list list = {0};
    int rc = cfn_describe_stack_events(client, "us-east-1", "proj-infra", 1, &list);
    CHECK(rc == 0, "describe stack events ok");
    expect_body(&f,
        "Action=DescribeStackEvents&Version=2010-05-15"
        "&StackName=proj-infra");
    CHECK(list.count == 1, "one event");
    if (list.count == 1) {
        CHECK(strcmp(list.items[0].event_id, "e1") == 0, "event id");
        CHECK(strcmp(list.items[0].resource_status, "CREATE_COMPLETE") == 0,
              "event status");
        CHECK(strcmp(list.items[0].resource_status_reason, "ok") == 0,
              "event reason");
    }
    cfn_event_list_free(&list);
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_error_mapping(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);

    const struct {
        const char *body;
        int expected;
    } cases[] = {
        {ERROR_NOT_FOUND, ENOENT},
        {ERROR_ACCESS, EACCES},
        {ERROR_CAPS, EPERM},
        {ERROR_NO_UPDATES, EALREADY},
        {ERROR_EXISTS, EEXIST},
        {ERROR_GENERIC, EIO},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        fake_clear(&f);
        fake_serve_status(&f, 400, cases[i].body);
        cfn_stack_list list = {0};
        int rc = cfn_describe_stacks(client, "us-east-1", "proj-infra", &list);
        CHECK(rc == cases[i].expected, "AWS error mapped");
        cfn_stack_list_free(&list);
    }

    fake_clear(&f);
    fake_serve(&f, "not xml");
    cfn_stack_list list = {0};
    CHECK(cfn_describe_stacks(client, "us-east-1", "proj-infra", &list) == EPROTO,
          "malformed response rejected");

    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_argument_validation(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    cfn_stack_list list = {0};
    CHECK(cfn_describe_stacks(NULL, "us-east-1", "s", &list) == EINVAL,
          "NULL client");
    CHECK(cfn_describe_stacks(client, NULL, "s", &list) == EINVAL, "NULL region");
    CHECK(cfn_describe_stacks(client, "us-east-1", "s", NULL) == EINVAL,
          "NULL out");
    cfn_change_set cs = {0};
    CHECK(cfn_describe_change_set(client, "us-east-1", "s", "", &cs) == EINVAL,
          "empty change set name");
    CHECK(f.count == 0, "invalid calls send nothing");
    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_wait_for_stack(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f, status_xml("CREATE_IN_PROGRESS", "working"));
    fake_serve(&f, status_xml("CREATE_COMPLETE", ""));
    int timed_out = -1;
    int rc = cfn_wait_for_stack(client, "us-east-1", "proj-infra",
                                CFN_WAIT_CREATE, 5, 0, &timed_out);
    CHECK(rc == 0 && timed_out == 0, "wait create success");
    CHECK(f.count == 2, "polled twice");

    fake_clear(&f);
    fake_serve(&f, status_xml("UPDATE_ROLLBACK_COMPLETE", "failed update"));
    timed_out = -1;
    rc = cfn_wait_for_stack(client, "us-east-1", "proj-infra",
                            CFN_WAIT_UPDATE, 5, 0, &timed_out);
    CHECK(rc == ECANCELED && timed_out == 0, "wait update failure aborts");

    fake_clear(&f);
    fake_serve(&f, status_xml("CREATE_IN_PROGRESS", "still"));
    timed_out = -1;
    rc = cfn_wait_for_stack(client, "us-east-1", "proj-infra",
                            CFN_WAIT_CREATE, 2, 0, &timed_out);
    CHECK(rc == 0 && timed_out == 1, "wait timeout is reported");

    fake_clear(&f);
    fake_serve_status(&f, 400, ERROR_NOT_FOUND);
    timed_out = -1;
    rc = cfn_wait_for_stack(client, "us-east-1", "proj-infra",
                            CFN_WAIT_DELETE, 2, 0, &timed_out);
    CHECK(rc == 0 && timed_out == 0, "delete waiter treats absent stack as done");

    cfn_client_destroy(client);
    fake_clear(&f);
}

static void test_wait_for_change_set(void)
{
    fake f = {0};
    cfn_client *client = make_client(&f);
    fake_serve(&f,
        "<DescribeChangeSetResponse><DescribeChangeSetResult>"
        "<Status>CREATE_IN_PROGRESS</Status></DescribeChangeSetResult>"
        "</DescribeChangeSetResponse>");
    fake_serve(&f, CHANGE_SET_EMPTY);
    int timed_out = -1;
    int rc = cfn_wait_for_change_set(client, "us-east-1", "proj-infra", "cs1",
                                     5, 0, &timed_out);
    CHECK(rc == 0 && timed_out == 0, "wait change set success");
    CHECK(f.count == 2, "change set polled twice");

    fake_clear(&f);
    fake_serve(&f,
        "<DescribeChangeSetResponse><DescribeChangeSetResult>"
        "<Status>FAILED</Status><StatusReason>bad template</StatusReason>"
        "</DescribeChangeSetResult></DescribeChangeSetResponse>");
    timed_out = -1;
    rc = cfn_wait_for_change_set(client, "us-east-1", "proj-infra", "cs1",
                                 2, 0, &timed_out);
    CHECK(rc == ECANCELED && timed_out == 0, "failed change set aborts wait");

    cfn_client_destroy(client);
    fake_clear(&f);
}

int main(void)
{
    test_client();
    test_status_mapping();
    test_describe_stacks();
    test_describe_stacks_pagination();
    test_create_change_set();
    test_create_change_set_validation();
    test_describe_change_set();
    test_execute_and_delete_change_set();
    test_template_summary();
    test_delete_stack();
    test_stack_resources();
    test_stack_events();
    test_error_mapping();
    test_argument_validation();
    test_wait_for_stack();
    test_wait_for_change_set();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("cfn tests passed\n");
    return 0;
}
