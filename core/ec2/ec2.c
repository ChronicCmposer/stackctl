/*
 * ec2.c — client lifecycle, the aws_request transport adapter, AWS error
 * reporting with spec §4 hints, and resource destructors.
 */

#include "ec2_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Production transport: every EC2 operation funnels into aws_request(). */
static int aws_transport(aws_ctx *aws, const aws_req *req, aws_resp *resp,
                         void *ud)
{
    (void)ud;
    return aws_request(aws, req, resp);
}

int ec2_client_init(ec2_client **out, aws_ctx *aws, const char *region)
{
    if (out == NULL || aws == NULL || region == NULL) {
        return EINVAL;
    }

    size_t region_length = strlen(region);
    if (region_length == 0 || region_length >= EC2_REGION_MAX) {
        return EINVAL;
    }

    ec2_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return ENOMEM;
    }
    client->aws = aws;
    memcpy(client->region, region, region_length + 1);
    client->transport = aws_transport;
    client->transport_ud = NULL;

    *out = client;
    return 0;
}

void ec2_client_free(ec2_client *client)
{
    free(client);
}

int ec2_call(ec2_client *client, const char *action, ec2_params *params,
             aws_resp *resp)
{
    if (client == NULL || action == NULL || params == NULL || resp == NULL) {
        return EINVAL;
    }

    const char *body = NULL;
    size_t length = 0;
    int rc = ec2_params_done(params, &body, &length);
    if (rc != 0) {
        return rc;
    }

    aws_req request = {
        .service = "ec2",
        .region = client->region,
        .method = "POST",
        .path = "/",
        .query = NULL,
        .body = body,
        .body_len = length,
        .content_type = "application/x-www-form-urlencoded",
        .unsigned_payload = 0,
    };

    rc = client->transport(client->aws, &request, resp, client->transport_ud);
    if (rc != 0) {
        return rc;
    }
    if (resp->status < 200 || resp->status >= 300) {
        return ec2_report_api_error(action, resp);
    }
    return 0;
}

static int is_capacity_error(const char *code)
{
    static const char *const capacity_codes[] = {
        "InsufficientInstanceCapacity",
        "MaxSpotInstanceCountExceeded",
        "SpotMaxPriceTooLow",
        "InsufficientCapacity",
        "InsufficientCapacityOnHost",
    };

    for (size_t i = 0; i < sizeof(capacity_codes) / sizeof(capacity_codes[0]);
         i++) {
        if (strcmp(code, capacity_codes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int ec2_report_api_error(const char *action, aws_resp *resp)
{
    char code[EC2_ERROR_CODE_MAX];
    char message[512];

    code[0] = '\0';
    message[0] = '\0';

    if (aws_error_code(resp, code) != 1) {
        snprintf(code, sizeof(code), "HTTP%ld",
                 resp != NULL ? resp->status : 0L);
    }
    if (resp != NULL && resp->body != NULL) {
        ec2_xml_span document = {resp->body, resp->body + resp->body_len};
        (void)ec2_xml_text(&document, "Message", message, sizeof(message));
    }

    fprintf(stderr, "stackctl: ec2 %s failed: %s%s%s\n",
            action != NULL ? action : "request", code, message[0] != '\0' ? ": " : "",
            message);

    if (is_capacity_error(code)) {
        fprintf(stderr,
                "stackctl: capacity error; retry with --no-spot or "
                "--instance-type <next allowlisted type>\n");
    } else if (strcmp(code, "UnauthorizedOperation") == 0) {
        fprintf(stderr,
                "stackctl: the project identity lacks ec2 permissions; "
                "re-run provision\n");
    }

    return EC2_ERR_AWS_API;
}

const char *ec2_instance_tag(const ec2_instance *instance, const char *key)
{
    if (instance == NULL || key == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < instance->tag_count; i++) {
        if (strcmp(instance->tags[i].key, key) == 0) {
            return instance->tags[i].value;
        }
    }
    return NULL;
}

void ec2_instance_list_free(ec2_instance_list *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

void ec2_image_list_free(ec2_image_list *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

void ec2_terminate_result_free(ec2_terminate_result *result)
{
    if (result == NULL) {
        return;
    }
    free(result->items);
    result->items = NULL;
    result->count = 0;
}

void ec2_string_free(char *string)
{
    free(string);
}
