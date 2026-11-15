/*
 * ec2_test.c — fake-transport tests for core/ec2.
 *
 * No network: a fake ec2_transport_fn captures the exact aws_req (service,
 * region, method, path, content type, form body) and replays canned XML/error
 * responses. Every public operation, its parameter encoding, XML parsing,
 * error mapping, idempotency field (ClientToken) and the aws_wait-based
 * waiters are pinned (CONTRACT Amendment 2/4).
 */

#include "ec2.h"
#include "ec2_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);    \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

typedef struct fake_step {
    long status;
    const char *body;
} fake_step;

typedef struct fake_transport {
    fake_step steps[8];
    size_t step_count;
    size_t step_index;
    int fail_with;
    size_t call_count;
    char service[32];
    char region[32];
    char method[16];
    char path[128];
    char content_type[64];
    char last_body[8192];
} fake_transport;

static int fake_send(aws_ctx *aws, const aws_req *req, aws_resp *resp, void *ud)
{
    fake_transport *fake = ud;
    (void)aws;

    fake->call_count++;
    snprintf(fake->service, sizeof fake->service, "%s",
             req->service != NULL ? req->service : "");
    snprintf(fake->region, sizeof fake->region, "%s",
             req->region != NULL ? req->region : "");
    snprintf(fake->method, sizeof fake->method, "%s",
             req->method != NULL ? req->method : "");
    snprintf(fake->path, sizeof fake->path, "%s",
             req->path != NULL ? req->path : "");
    snprintf(fake->content_type, sizeof fake->content_type, "%s",
             req->content_type != NULL ? req->content_type : "");
    if (req->body != NULL) {
        size_t len = req->body_len;
        if (len >= sizeof fake->last_body) {
            len = sizeof fake->last_body - 1;
        }
        memcpy(fake->last_body, req->body, len);
        fake->last_body[len] = '\0';
    } else {
        fake->last_body[0] = '\0';
    }

    if (fake->fail_with != 0) {
        return fake->fail_with;
    }
    if (fake->step_count == 0) {
        return EIO;
    }
    size_t index = fake->step_index;
    if (index >= fake->step_count) {
        index = fake->step_count - 1;
    }
    fake->step_index++;

    const fake_step *step = &fake->steps[index];
    resp->status = step->status;
    if (step->body != NULL) {
        size_t len = strlen(step->body);
        resp->body = malloc(len + 1);
        if (resp->body == NULL) {
            return ENOMEM;
        }
        memcpy(resp->body, step->body, len + 1);
        resp->body_len = len;
    }
    return 0;
}

/* aws_ctx is opaque and never dereferenced by the fake transport. */
static char fake_aws_storage;

static ec2_client *make_client(fake_transport *fake)
{
    ec2_client *client = NULL;
    int rc = ec2_client_init(&client, (aws_ctx *)&fake_aws_storage, "us-east-1");

    CHECK(rc == 0 && client != NULL, "client initialises");
    if (client == NULL) {
        return NULL;
    }
    CHECK(client->transport != NULL, "client has a default transport");
    client->transport = fake_send;
    client->transport_ud = fake;
    return client;
}

static int body_has(const fake_transport *fake, const char *needle)
{
    return strstr(fake->last_body, needle) != NULL;
}

static size_t body_count(const fake_transport *fake, const char *needle)
{
    size_t count = 0;
    size_t needle_len = strlen(needle);
    const char *cursor = fake->last_body;
    while ((cursor = strstr(cursor, needle)) != NULL) {
        count++;
        cursor += needle_len;
    }
    return count;
}

static ec2_run_spec valid_spec(void)
{
    ec2_run_spec spec = {
        .ami_id = "ami-0123456789abcdef0",
        .instance_type = "g4dn.xlarge",
        .key_name = "my-key",
        .subnet_id = "subnet-1",
        .security_group_id = "sg-1",
        .instance_profile_name = "proj-instance-profile",
        .client_token = "0123456789abcdef",
        .project = "proj",
        .name = "host.example.com",
        .launch_nonce = "nonce1",
        .root_device_name = "/dev/xvda",
        .root_volume_type = NULL,
        .root_volume_size_gb = 100,
        .spot = 0,
    };
    return spec;
}

static void test_client_init(void)
{
    ec2_client *client = NULL;

    CHECK(ec2_client_init(&client, (aws_ctx *)&fake_aws_storage, "us-east-1") == 0,
          "client init succeeds");
    ec2_client_free(client);
    ec2_client_free(NULL);

    CHECK(ec2_client_init(NULL, (aws_ctx *)&fake_aws_storage, "us-east-1") == EINVAL,
          "NULL out is EINVAL");
    CHECK(ec2_client_init(&client, NULL, "us-east-1") == EINVAL,
          "NULL aws context is EINVAL");
    CHECK(ec2_client_init(&client, (aws_ctx *)&fake_aws_storage, "") == EINVAL,
          "empty region is EINVAL");
    CHECK(ec2_client_init(&client, (aws_ctx *)&fake_aws_storage, NULL) == EINVAL,
          "NULL region is EINVAL");
}

static void test_run_instances_on_demand(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<RunInstancesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\">"
                "<reservationId>r-1</reservationId><instancesSet><item>"
                "<instanceId>i-0123456789abcdef0</instanceId>"
                "<imageId>ami-0123456789abcdef0</imageId>"
                "<instanceType>g4dn.xlarge</instanceType>"
                "<instanceState><code>0</code><name>pending</name></instanceState>"
                "<privateIpAddress>10.0.0.5</privateIpAddress><ipAddress/>"
                "</item></instancesSet></RunInstancesResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    ec2_run_spec spec = valid_spec();
    ec2_run_result result;
    memset(&result, 0, sizeof result);

    CHECK(ec2_run_instances(client, &spec, &result) == 0, "run_instances succeeds");
    CHECK(fake->call_count == 1, "one RunInstances call");
    CHECK(strcmp(fake->service, "ec2") == 0, "service is ec2");
    CHECK(strcmp(fake->region, "us-east-1") == 0, "region is the client region");
    CHECK(strcmp(fake->method, "POST") == 0, "EC2 Query uses POST");
    CHECK(strcmp(fake->path, "/") == 0, "path is /");
    CHECK(strcmp(fake->content_type, "application/x-www-form-urlencoded") == 0,
          "form content type");

    CHECK(body_has(fake, "Action=RunInstances&"), "action parameter");
    CHECK(body_has(fake, "Version=" EC2_API_VERSION), "api version parameter");
    CHECK(body_has(fake, "ImageId=ami-0123456789abcdef0"), "ImageId");
    CHECK(body_has(fake, "InstanceType=g4dn.xlarge"), "InstanceType");
    CHECK(body_has(fake, "KeyName=my-key"), "KeyName");
    CHECK(body_has(fake, "MinCount=1&MaxCount=1"), "exactly one instance");
    CHECK(body_has(fake, "ClientToken=0123456789abcdef"), "ClientToken idempotency");
    CHECK(body_has(fake, "SubnetId=subnet-1"), "SubnetId");
    CHECK(body_has(fake, "SecurityGroupId.1=sg-1"), "SecurityGroupId.1");
    CHECK(body_has(fake, "IamInstanceProfile.Name=proj-instance-profile"),
          "instance profile is wired by name");
    CHECK(body_has(fake, "MetadataOptions.HttpEndpoint=enabled"),
          "IMDSv2 endpoint is enabled");
    CHECK(body_has(fake, "MetadataOptions.HttpTokens=required"),
          "IMDSv2 tokens are required");
    CHECK(body_has(fake, "MetadataOptions.HttpPutResponseHopLimit=2"),
          "IMDSv2 hop limit is 2 for bridged containers");
    CHECK(body_has(fake, "BlockDeviceMapping.1.DeviceName=%2Fdev%2Fxvda"),
          "root device name is percent-encoded");
    CHECK(body_has(fake, "BlockDeviceMapping.1.Ebs.VolumeSize=100"),
          "root volume size");
    CHECK(body_has(fake, "BlockDeviceMapping.1.Ebs.VolumeType=gp3"),
          "gp3 is the default root volume type");
    CHECK(body_has(fake, "BlockDeviceMapping.1.Ebs.Encrypted=true"),
          "root volume encryption invariant");
    CHECK(body_has(fake, "BlockDeviceMapping.1.Ebs.DeleteOnTermination=true"),
          "root volume delete-on-termination invariant");
    CHECK(body_has(fake, "TagSpecifications.1.ResourceType=instance"),
          "tag specification targets the instance resource only");
    CHECK(body_count(fake, "TagSpecifications.1.Tag.") == 6,
          "three tag key/value pairs are emitted");
    CHECK(body_count(fake, ".Key=") == 3, "exactly three tag keys");
    CHECK(body_has(fake, "TagSpecifications.1.Tag.1.Key=Project"),
          "Project tag key");
    CHECK(body_has(fake, "TagSpecifications.1.Tag.1.Value=proj"), "Project tag value");
    CHECK(body_has(fake, "TagSpecifications.1.Tag.2.Key=Name"), "Name tag key");
    CHECK(body_has(fake, "TagSpecifications.1.Tag.2.Value=host.example.com"),
          "Name tag value");
    CHECK(body_has(fake, "TagSpecifications.1.Tag.3.Key=stackctl%3Alaunch-nonce"),
          "launch-nonce tag key percent-encoded");
    CHECK(body_has(fake, "TagSpecifications.1.Tag.3.Value=nonce1"),
          "launch-nonce tag value");
    CHECK(!body_has(fake, "ResourceType=volume"), "never tags the volume");
    CHECK(!body_has(fake, "InstanceMarketOptions"), "on-demand omits market options");

    CHECK(strcmp(result.instance_id, "i-0123456789abcdef0") == 0,
          "run result instance id");
    CHECK(strcmp(result.state, "pending") == 0, "run result state");
    CHECK(strcmp(result.private_ip, "10.0.0.5") == 0, "run result private ip");
    CHECK(result.public_ip[0] == '\0', "run result public ip empty until assigned");

    ec2_client_free(client);
}

static void test_run_instances_spot(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<RunInstancesResponse><instancesSet><item>"
                "<instanceId>i-spot</instanceId>"
                "<instanceState><name>pending</name></instanceState>"
                "</item></instancesSet></RunInstancesResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    ec2_run_spec spec = valid_spec();
    spec.spot = 1;
    spec.root_volume_type = "gp2";
    ec2_run_result result;

    CHECK(ec2_run_instances(client, &spec, &result) == 0, "spot run succeeds");
    CHECK(body_has(fake, "InstanceMarketOptions.MarketType=spot"), "spot market type");
    CHECK(body_has(fake,
                   "InstanceMarketOptions.SpotOptions.InstanceInterruptionBehavior="
                   "terminate"),
          "spot interruption behavior is terminate");
    CHECK(body_has(fake, "InstanceMarketOptions.SpotOptions.SpotInstanceType=one-time"),
          "spot request is one-time");
    CHECK(!body_has(fake, "MaxPrice"), "spot requests omit MaxPrice");
    CHECK(body_has(fake, "BlockDeviceMapping.1.Ebs.VolumeType=gp2"),
          "explicit root volume type is honoured");

    ec2_client_free(client);
}

static void test_run_instances_validation(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    ec2_run_spec spec = valid_spec();
    ec2_run_result result;

    CHECK(ec2_run_instances(client, NULL, &result) == EINVAL, "NULL spec is EINVAL");

    spec = valid_spec();
    spec.ami_id = NULL;
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL, "missing AMI is EINVAL");

    spec = valid_spec();
    spec.client_token = "";
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL,
          "missing ClientToken is EINVAL");

    spec = valid_spec();
    spec.client_token = "0123456789012345678901234567890123456789012345678901234567890123x";
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL,
          "over-long ClientToken is EINVAL");

    spec = valid_spec();
    spec.root_volume_size_gb = 0;
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL,
          "non-positive root volume size is EINVAL");

    spec = valid_spec();
    spec.root_device_name = NULL;
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL,
          "missing root device name is EINVAL");

    spec = valid_spec();
    spec.instance_profile_name = NULL;
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL,
          "missing instance profile is EINVAL");

    spec = valid_spec();
    spec.project = NULL;
    CHECK(ec2_run_instances(client, &spec, &result) == EINVAL,
          "missing Project tag is EINVAL");

    CHECK(fake->call_count == 0, "validation fails before any request");

    CHECK(ec2_run_instances(NULL, &spec, &result) == EINVAL,
          "NULL client is EINVAL");

    ec2_client_free(client);
}

static void test_run_instances_api_errors(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 400,
        .body = "<Response><Errors><Error>"
                "<Code>InsufficientInstanceCapacity</Code>"
                "<Message>no capacity in us-east-1a</Message>"
                "</Error></Errors><RequestID>req-1</RequestID></Response>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    ec2_run_spec spec = valid_spec();
    ec2_run_result result;
    memset(&result, 0, sizeof result);

    CHECK(ec2_run_instances(client, &spec, &result) == EC2_ERR_AWS_API,
          "capacity rejection maps to the AWS API error code");
    CHECK(result.instance_id[0] == '\0', "failed run leaves out untouched");

    ec2_client_free(client);
}

static void test_describe_instances(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse>"
                "<reservationSet><item><instancesSet>"
                "<item>"
                "<instanceId>i-1</instanceId><imageId>ami-1</imageId>"
                "<instanceType>g4dn.xlarge</instanceType>"
                "<instanceState><code>16</code><name>running</name></instanceState>"
                "<privateIpAddress>10.0.0.10</privateIpAddress>"
                "<ipAddress>203.0.113.10</ipAddress>"
                "<tagSet>"
                "<item><key>Project</key><value>proj</value></item>"
                "<item><key>stackctl:launch-nonce</key><value>n1</value></item>"
                "</tagSet>"
                "</item>"
                "<item>"
                "<instanceId>i-2</instanceId><imageId>ami-2</imageId>"
                "<instanceType>t3.micro</instanceType>"
                "<instanceState><code>80</code><name>stopped</name></instanceState>"
                "<privateIpAddress>10.0.0.11</privateIpAddress>"
                "<tagSet><item><key>Project</key><value>proj</value></item></tagSet>"
                "</item>"
                "</instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    const char *id_values[] = {"i-1", "i-2"};
    const char *project_values[] = {"proj"};
    ec2_filter filters[] = {
        {.name = "instance-id", .values = id_values, .value_count = 2},
        {.name = "tag:Project", .values = project_values, .value_count = 1},
    };
    ec2_instance_list list;
    memset(&list, 0, sizeof list);

    CHECK(ec2_describe_instances(client, filters, ARRAY_LEN(filters), &list) == 0,
          "describe_instances succeeds");
    CHECK(body_has(fake, "Action=DescribeInstances&"), "action");
    CHECK(body_has(fake, "Filter.1.Name=instance-id&Filter.1.Value.1=i-1"
                         "&Filter.1.Value.2=i-2"),
          "multi-value instance-id filter");
    CHECK(body_has(fake, "Filter.2.Name=tag%3AProject&Filter.2.Value.1=proj"),
          "tag filter name is percent-encoded");

    CHECK(list.count == 2, "two instances parsed");
    if (list.count == 2) {
        CHECK(strcmp(list.items[0].instance_id, "i-1") == 0, "first id");
        CHECK(strcmp(list.items[0].state, "running") == 0, "first state");
        CHECK(strcmp(list.items[0].image_id, "ami-1") == 0, "first image id");
        CHECK(strcmp(list.items[0].instance_type, "g4dn.xlarge") == 0,
              "first instance type");
        CHECK(strcmp(list.items[0].private_ip, "10.0.0.10") == 0, "first private ip");
        CHECK(strcmp(list.items[0].public_ip, "203.0.113.10") == 0, "first public ip");
        CHECK(list.items[0].tag_count == 2, "first instance has two tags");
        CHECK(strcmp(list.items[1].instance_id, "i-2") == 0, "second id");
        CHECK(strcmp(list.items[1].state, "stopped") == 0, "second state");
        CHECK(list.items[1].public_ip[0] == '\0', "stopped instance has no public ip");
        CHECK(list.items[1].tag_count == 1, "second instance has one tag");

        const char *nonce = ec2_instance_tag(&list.items[0], "stackctl:launch-nonce");
        CHECK(nonce != NULL && strcmp(nonce, "n1") == 0, "tag lookup by key");
        CHECK(ec2_instance_tag(&list.items[0], "absent") == NULL,
              "absent tag lookup is NULL");
        CHECK(ec2_instance_tag(NULL, "Project") == NULL, "NULL instance tag is NULL");
    }

    ec2_instance_list_free(&list);
    CHECK(list.items == NULL && list.count == 0, "list free zeroes the list");

    /* Empty result set is success. */
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet/>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 1;
    client->transport_ud = fake;
    memset(&list, 0, sizeof list);
    CHECK(ec2_describe_instances(client, NULL, 0, &list) == 0,
          "empty describe succeeds");
    CHECK(list.count == 0, "empty describe has zero instances");
    ec2_instance_list_free(&list);

    /* Malformed body is EBADMSG, not a silent empty list. */
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){.status = 200, .body = "<SomethingElse/>"};
    fake->step_count = 1;
    CHECK(ec2_describe_instances(client, NULL, 0, &list) == EBADMSG,
          "malformed describe body is EBADMSG");

    ec2_client_free(client);
}

static void test_terminate_instances(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<TerminateInstancesResponse><instancesSet>"
                "<item><instanceId>i-1</instanceId>"
                "<currentState><code>32</code><name>shutting-down</name></currentState>"
                "<previousState><code>16</code><name>running</name></previousState></item>"
                "<item><instanceId>i-2</instanceId>"
                "<currentState><code>48</code><name>terminated</name></currentState>"
                "</item>"
                "</instancesSet></TerminateInstancesResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    const char *ids[] = {"i-1", "i-2"};
    ec2_terminate_result result;
    memset(&result, 0, sizeof result);

    CHECK(ec2_terminate_instances(client, ids, 2, &result) == 0,
          "terminate_instances succeeds");
    CHECK(body_has(fake, "Action=TerminateInstances&"), "terminate action");
    CHECK(body_has(fake, "InstanceId.1=i-1&InstanceId.2=i-2"), "instance ids");
    CHECK(result.count == 2, "two termination entries");
    if (result.count == 2) {
        CHECK(strcmp(result.items[0].instance_id, "i-1") == 0, "first terminated id");
        CHECK(strcmp(result.items[0].state, "shutting-down") == 0,
              "first current state");
        CHECK(strcmp(result.items[1].state, "terminated") == 0,
              "already-terminated instance is idempotent");
    }
    ec2_terminate_result_free(&result);
    CHECK(result.items == NULL && result.count == 0, "terminate free zeroes");

    CHECK(ec2_terminate_instances(client, ids, 0, &result) == EINVAL,
          "zero ids is EINVAL");
    CHECK(ec2_terminate_instances(client, NULL, 2, &result) == EINVAL,
          "NULL ids is EINVAL");

    ec2_client_free(client);
}

static void test_describe_images(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeImagesResponse><imagesSet><item>"
                "<imageId>ami-1</imageId><imageState>available</imageState>"
                "<name>deep-learning-amd64</name><architecture>x86_64</architecture>"
                "<rootDeviceName>/dev/xvda</rootDeviceName>"
                "</item></imagesSet></DescribeImagesResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    const char *ids[] = {"ami-1", "ami-2"};
    ec2_image_list list;
    memset(&list, 0, sizeof list);

    CHECK(ec2_describe_images(client, ids, 2, &list) == 0, "describe_images succeeds");
    CHECK(body_has(fake, "Action=DescribeImages&"), "image action");
    CHECK(body_has(fake, "ImageId.1=ami-1&ImageId.2=ami-2"), "image ids encoded");
    CHECK(list.count == 1, "one image parsed");
    if (list.count == 1) {
        CHECK(strcmp(list.items[0].image_id, "ami-1") == 0, "image id");
        CHECK(strcmp(list.items[0].state, "available") == 0, "image state");
        CHECK(strcmp(list.items[0].name, "deep-learning-amd64") == 0, "image name");
        CHECK(strcmp(list.items[0].architecture, "x86_64") == 0, "image architecture");
        CHECK(strcmp(list.items[0].root_device_name, "/dev/xvda") == 0,
              "image root device name");
    }
    ec2_image_list_free(&list);

    CHECK(ec2_describe_images(client, ids, 0, &list) == EINVAL,
          "zero image ids is EINVAL");

    ec2_client_free(client);
}

static void test_console_output(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<GetConsoleOutputResponse><instanceId>i-1</instanceId>"
                "<timestamp>2026-11-15T00:00:00.000Z</timestamp>"
                "<output>QkVHSU4gU1NIIEhPU1QgS0VZIEZJTkdFUlBSSU5UUwo=</output>"
                "</GetConsoleOutputResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    char *output = NULL;
    CHECK(ec2_get_console_output(client, "i-1", &output) == 0,
          "get_console_output succeeds");
    CHECK(body_has(fake, "Action=GetConsoleOutput&"), "console action");
    CHECK(body_has(fake, "InstanceId=i-1"), "console instance id");
    CHECK(body_has(fake, "Latest=true"), "console Latest flag");
    CHECK(output != NULL &&
              strcmp(output, "BEGIN SSH HOST KEY FINGERPRINTS\n") == 0,
          "console output is base64-decoded");
    ec2_string_free(output);

    /* No output yet: success with a NULL string so callers keep polling. */
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<GetConsoleOutputResponse><instanceId>i-1</instanceId>"
                "<output/></GetConsoleOutputResponse>",
    };
    fake->step_count = 1;
    output = (char *)"sentinel";
    CHECK(ec2_get_console_output(client, "i-1", &output) == 0,
          "missing output is still success");
    CHECK(output == NULL, "missing output yields NULL");

    CHECK(ec2_get_console_output(client, "", &output) == EINVAL,
          "empty instance id is EINVAL");
    CHECK(ec2_get_console_output(client, NULL, &output) == EINVAL,
          "NULL instance id is EINVAL");

    ec2_client_free(client);
}

static void test_tags(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<CreateTagsResponse><return>true</return></CreateTagsResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    const char *ids[] = {"i-1", "i-2"};
    ec2_tag tags[] = {
        {.key = "Project", .value = "proj"},
        {.key = "Name", .value = "host.example.com"},
    };

    CHECK(ec2_tag_instances(client, ids, 2, tags, 2) == 0, "CreateTags succeeds");
    CHECK(body_has(fake, "Action=CreateTags&"), "create-tags action");
    CHECK(body_has(fake, "ResourceId.1=i-1&ResourceId.2=i-2"), "create-tags ids");
    CHECK(body_has(fake, "Tag.1.Key=Project&Tag.1.Value=proj"), "first tag");
    CHECK(body_has(fake, "Tag.2.Key=Name&Tag.2.Value=host.example.com"), "second tag");
    CHECK(ec2_tag_instances(client, ids, 2, tags, 0) == EINVAL,
          "zero tags is EINVAL");
    CHECK(ec2_tag_instances(client, ids, 0, tags, 2) == EINVAL,
          "zero ids is EINVAL");

    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DeleteTagsResponse><return>true</return></DeleteTagsResponse>",
    };
    fake->step_count = 1;

    const char *keys[] = {"Name", "stackctl:launch-nonce"};
    CHECK(ec2_untag_instances(client, &ids[0], 1, keys, 2) == 0,
          "DeleteTags succeeds");
    CHECK(body_has(fake, "Action=DeleteTags&"), "delete-tags action");
    CHECK(body_has(fake, "ResourceId.1=i-1"), "delete-tags id");
    CHECK(body_has(fake, "Tag.1.Key=Name&Tag.2.Key=stackctl%3Alaunch-nonce"),
          "delete-tags keys are percent-encoded");
    CHECK(!body_has(fake, "Tag.1.Value"), "delete-tags omits values");
    CHECK(ec2_untag_instances(client, &ids[0], 1, keys, 0) == EINVAL,
          "zero tag keys is EINVAL");

    ec2_client_free(client);
}

static void test_wait_running(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet><item>"
                "<instanceId>i-1</instanceId>"
                "<instanceState><name>pending</name></instanceState>"
                "<privateIpAddress>10.0.0.10</privateIpAddress>"
                "</item></instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->steps[1] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet><item>"
                "<instanceId>i-1</instanceId>"
                "<instanceState><name>running</name></instanceState>"
                "<privateIpAddress>10.0.0.10</privateIpAddress>"
                "<ipAddress>203.0.113.10</ipAddress>"
                "</item></instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 2;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    ec2_instance instance;
    int timed_out = -1;
    memset(&instance, 0, sizeof instance);

    CHECK(ec2_wait_running_with_public_ip(client, "i-1", 3, 0, &instance,
                                          &timed_out) == 0,
          "running waiter returns 0");
    CHECK(timed_out == 0, "running waiter did not time out");
    CHECK(fake->call_count == 2, "running waiter polled twice");
    CHECK(strcmp(instance.instance_id, "i-1") == 0, "waiter instance id");
    CHECK(strcmp(instance.state, "running") == 0, "waiter final state");
    CHECK(strcmp(instance.public_ip, "203.0.113.10") == 0, "waiter public ip");
    CHECK(body_has(fake, "Filter.1.Name=instance-id&Filter.1.Value.1=i-1"),
          "waiter filters by instance id");

    /* Exhaustion reports timed_out and keeps the last observation. */
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet><item>"
                "<instanceId>i-1</instanceId>"
                "<instanceState><name>pending</name></instanceState>"
                "</item></instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 1;
    memset(&instance, 0, sizeof instance);
    timed_out = -1;
    CHECK(ec2_wait_running_with_public_ip(client, "i-1", 2, 0, &instance,
                                          &timed_out) == 0,
          "exhausted waiter returns 0");
    CHECK(timed_out == 1, "exhausted waiter reports timeout");
    CHECK(fake->call_count == 2, "exhausted waiter polls to the cap");
    CHECK(strcmp(instance.state, "pending") == 0, "timeout keeps last state");

    CHECK(ec2_wait_running_with_public_ip(client, NULL, 2, 0, &instance,
                                          &timed_out) == EINVAL,
          "NULL instance id waiter is EINVAL");

    ec2_client_free(client);
}

static void test_wait_terminated(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet>"
                "<item><instanceId>i-1</instanceId>"
                "<instanceState><name>terminated</name></instanceState></item>"
                "<item><instanceId>i-2</instanceId>"
                "<instanceState><name>terminated</name></instanceState></item>"
                "</instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 1;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    const char *ids[] = {"i-1", "i-2"};
    int timed_out = -1;

    CHECK(ec2_wait_terminated(client, ids, 2, 3, 0, &timed_out) == 0,
          "terminated waiter returns 0");
    CHECK(timed_out == 0, "terminated waiter did not time out");
    CHECK(fake->call_count == 1, "terminated waiter needs one poll");
    CHECK(body_has(fake, "Filter.1.Value.1=i-1&Filter.1.Value.2=i-2"),
          "terminated waiter filters by all ids");

    /* One instance still running: keep polling. */
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet>"
                "<item><instanceId>i-1</instanceId>"
                "<instanceState><name>shutting-down</name></instanceState></item>"
                "<item><instanceId>i-2</instanceId>"
                "<instanceState><name>terminated</name></instanceState></item>"
                "</instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->steps[1] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet>"
                "<item><instanceId>i-1</instanceId>"
                "<instanceState><name>terminated</name></instanceState></item>"
                "<item><instanceId>i-2</instanceId>"
                "<instanceState><name>terminated</name></instanceState></item>"
                "</instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 2;
    timed_out = -1;
    CHECK(ec2_wait_terminated(client, ids, 2, 3, 0, &timed_out) == 0,
          "terminated waiter polls until all terminated");
    CHECK(timed_out == 0, "second terminated wait did not time out");
    CHECK(fake->call_count == 2, "terminated waiter polled twice");

    /* Exhaustion. */
    memset(fake, 0, sizeof *fake);
    fake->steps[0] = (fake_step){
        .status = 200,
        .body = "<DescribeInstancesResponse><reservationSet><item><instancesSet>"
                "<item><instanceId>i-1</instanceId>"
                "<instanceState><name>running</name></instanceState></item>"
                "</instancesSet></item></reservationSet>"
                "</DescribeInstancesResponse>",
    };
    fake->step_count = 1;
    timed_out = -1;
    CHECK(ec2_wait_terminated(client, ids, 2, 2, 0, &timed_out) == 0,
          "exhausted terminate waiter returns 0");
    CHECK(timed_out == 1, "exhausted terminate waiter reports timeout");

    CHECK(ec2_wait_terminated(client, ids, 0, 2, 0, &timed_out) == EINVAL,
          "zero ids waiter is EINVAL");

    ec2_client_free(client);
}

static void test_waiter_propagates_errors(fake_transport *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->fail_with = ECONNRESET;
    ec2_client *client = make_client(fake);
    if (client == NULL) {
        return;
    }

    ec2_instance instance;
    int timed_out = -1;
    CHECK(ec2_wait_running_with_public_ip(client, "i-1", 3, 0, &instance,
                                          &timed_out) == ECONNRESET,
          "waiter propagates transport errors");

    ec2_client_free(client);
}

int main(void)
{
    fake_transport fake;

    test_client_init();
    test_run_instances_on_demand(&fake);
    test_run_instances_spot(&fake);
    test_run_instances_validation(&fake);
    test_run_instances_api_errors(&fake);
    test_describe_instances(&fake);
    test_terminate_instances(&fake);
    test_describe_images(&fake);
    test_console_output(&fake);
    test_tags(&fake);
    test_wait_running(&fake);
    test_wait_terminated(&fake);
    test_waiter_propagates_errors(&fake);

    if (failures != 0) {
        fprintf(stderr, "%d ec2 test(s) failed\n", failures);
        return 1;
    }
    printf("ec2_test: all tests passed\n");
    return 0;
}
