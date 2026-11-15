/*
 * instances.c — RunInstances, DescribeInstances, TerminateInstances and the
 * aws_wait-based waiters (spec §4 launch/terminate).
 */

#include "ec2_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Shared response parsing                                                   */
/* ------------------------------------------------------------------------- */

static int parse_instance(const ec2_xml_span *item, ec2_instance *out)
{
    memset(out, 0, sizeof(*out));

    if (!ec2_xml_text(item, "instanceId", out->instance_id,
                      sizeof(out->instance_id))) {
        return 0;
    }
    (void)ec2_xml_text(item, "imageId", out->image_id, sizeof(out->image_id));
    (void)ec2_xml_text(item, "instanceType", out->instance_type,
                       sizeof(out->instance_type));
    (void)ec2_xml_text(item, "privateIpAddress", out->private_ip,
                       sizeof(out->private_ip));
    (void)ec2_xml_text(item, "ipAddress", out->public_ip,
                       sizeof(out->public_ip));

    ec2_xml_span state;
    const char *next = NULL;
    if (ec2_xml_next(item->begin, item->end, "instanceState", &state, &next)) {
        (void)ec2_xml_text(&state, "name", out->state, sizeof(out->state));
    }

    ec2_xml_span tag_set;
    if (!ec2_xml_next(item->begin, item->end, "tagSet", &tag_set, &next)) {
        return 1;
    }

    const char *cursor = tag_set.begin;
    while (out->tag_count < EC2_MAX_TAGS) {
        ec2_xml_span tag_item;
        if (!ec2_xml_next(cursor, tag_set.end, "item", &tag_item, &cursor)) {
            break;
        }
        ec2_tag *tag = &out->tags[out->tag_count];
        (void)ec2_xml_text(&tag_item, "key", tag->key, sizeof(tag->key));
        (void)ec2_xml_text(&tag_item, "value", tag->value, sizeof(tag->value));
        if (tag->key[0] != '\0') {
            out->tag_count++;
        }
    }
    return 1;
}

static int instance_list_append(ec2_instance_list *list,
                                const ec2_instance *instance)
{
    ec2_instance *grown =
        realloc(list->items, (list->count + 1) * sizeof(*grown));
    if (grown == NULL) {
        return ENOMEM;
    }
    list->items = grown;
    list->items[list->count] = *instance;
    list->count++;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* RunInstances                                                              */
/* ------------------------------------------------------------------------- */

static int nonempty(const char *value)
{
    return value != NULL && value[0] != '\0';
}

static int validate_run_spec(const ec2_run_spec *spec)
{
    if (spec == NULL) {
        return EINVAL;
    }
    if (!nonempty(spec->ami_id) || !nonempty(spec->instance_type) ||
        !nonempty(spec->key_name) || !nonempty(spec->subnet_id) ||
        !nonempty(spec->security_group_id) ||
        !nonempty(spec->instance_profile_name) ||
        !nonempty(spec->client_token) || !nonempty(spec->project) ||
        !nonempty(spec->name) || !nonempty(spec->launch_nonce) ||
        !nonempty(spec->root_device_name)) {
        return EINVAL;
    }
    size_t token_length = strlen(spec->client_token);
    if (token_length > 64) {
        return EINVAL;
    }
    if (spec->root_volume_size_gb <= 0) {
        return EINVAL;
    }
    return 0;
}

static int build_run_request(const ec2_run_spec *spec, ec2_params *params)
{
    const char *volume_type =
        spec->root_volume_type != NULL ? spec->root_volume_type : "gp3";
    int rc = 0;

    rc |= ec2_params_add(params, "Action", "RunInstances");
    rc |= ec2_params_add(params, "Version", EC2_API_VERSION);
    rc |= ec2_params_add(params, "ImageId", spec->ami_id);
    rc |= ec2_params_add(params, "InstanceType", spec->instance_type);
    rc |= ec2_params_add(params, "KeyName", spec->key_name);
    rc |= ec2_params_add_int(params, "MinCount", 1);
    rc |= ec2_params_add_int(params, "MaxCount", 1);
    rc |= ec2_params_add(params, "ClientToken", spec->client_token);
    rc |= ec2_params_add(params, "SubnetId", spec->subnet_id);
    rc |= ec2_params_add(params, "SecurityGroupId.1", spec->security_group_id);
    rc |= ec2_params_add(params, "IamInstanceProfile.Name",
                         spec->instance_profile_name);

    rc |= ec2_params_add(params, "BlockDeviceMapping.1.DeviceName",
                         spec->root_device_name);
    rc |= ec2_params_add_int(params, "BlockDeviceMapping.1.Ebs.VolumeSize",
                             spec->root_volume_size_gb);
    rc |= ec2_params_add(params, "BlockDeviceMapping.1.Ebs.VolumeType",
                         volume_type);
    rc |= ec2_params_add(params, "BlockDeviceMapping.1.Ebs.Encrypted", "true");
    rc |= ec2_params_add(params, "BlockDeviceMapping.1.Ebs.DeleteOnTermination",
                         "true");

    if (spec->spot) {
        rc |= ec2_params_add(params, "InstanceMarketOptions.MarketType", "spot");
        rc |= ec2_params_add(
            params, "InstanceMarketOptions.SpotOptions.InstanceInterruptionBehavior",
            "terminate");
        rc |= ec2_params_add(
            params, "InstanceMarketOptions.SpotOptions.SpotInstanceType",
            "one-time");
        /* MaxPrice is deliberately omitted: AWS defaults to the on-demand cap. */
    }

    rc |= ec2_params_add(params, "TagSpecifications.1.ResourceType", "instance");
    rc |= ec2_params_add(params, "TagSpecifications.1.Tag.1.Key", "Project");
    rc |= ec2_params_add(params, "TagSpecifications.1.Tag.1.Value", spec->project);
    rc |= ec2_params_add(params, "TagSpecifications.1.Tag.2.Key", "Name");
    rc |= ec2_params_add(params, "TagSpecifications.1.Tag.2.Value", spec->name);
    rc |= ec2_params_add(params, "TagSpecifications.1.Tag.3.Key",
                         "stackctl:launch-nonce");
    rc |= ec2_params_add(params, "TagSpecifications.1.Tag.3.Value",
                         spec->launch_nonce);

    return rc != 0 ? ENOMEM : 0;
}

int ec2_run_instances(ec2_client *client, const ec2_run_spec *spec,
                      ec2_run_result *out)
{
    if (client == NULL || out == NULL) {
        return EINVAL;
    }
    int rc = validate_run_spec(spec);
    if (rc != 0) {
        return rc;
    }

    ec2_params params;
    ec2_params_init(&params);
    rc = build_run_request(spec, &params);
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "RunInstances", &params, &response);
        if (rc == 0) {
            ec2_xml_span document = {response.body,
                                     response.body + response.body_len};
            ec2_xml_span set;
            const char *next = NULL;
            ec2_instance instance;
            if (!ec2_xml_next(document.begin, document.end, "instancesSet", &set,
                              &next) ||
                !ec2_xml_next(set.begin, set.end, "item", &set, &next) ||
                !parse_instance(&set, &instance)) {
                rc = EBADMSG;
            } else {
                memset(out, 0, sizeof(*out));
                memcpy(out->instance_id, instance.instance_id,
                       sizeof(out->instance_id));
                memcpy(out->state, instance.state, sizeof(out->state));
                memcpy(out->private_ip, instance.private_ip,
                       sizeof(out->private_ip));
                memcpy(out->public_ip, instance.public_ip,
                       sizeof(out->public_ip));
            }
        }
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* DescribeInstances                                                         */
/* ------------------------------------------------------------------------- */

static int validate_filters(const ec2_filter *filters, size_t filter_count)
{
    if (filter_count > 0 && filters == NULL) {
        return EINVAL;
    }
    for (size_t i = 0; i < filter_count; i++) {
        if (!nonempty(filters[i].name) || filters[i].value_count == 0 ||
            filters[i].values == NULL) {
            return EINVAL;
        }
        for (size_t j = 0; j < filters[i].value_count; j++) {
            if (filters[i].values[j] == NULL) {
                return EINVAL;
            }
        }
    }
    return 0;
}

static int build_describe_request(const ec2_filter *filters,
                                  size_t filter_count, ec2_params *params)
{
    int rc = 0;
    char key[64];

    rc |= ec2_params_add(params, "Action", "DescribeInstances");
    rc |= ec2_params_add(params, "Version", EC2_API_VERSION);
    for (size_t i = 0; i < filter_count; i++) {
        snprintf(key, sizeof(key), "Filter.%zu.Name", i + 1);
        rc |= ec2_params_add(params, key, filters[i].name);
        for (size_t j = 0; j < filters[i].value_count; j++) {
            snprintf(key, sizeof(key), "Filter.%zu.Value.%zu", i + 1, j + 1);
            rc |= ec2_params_add(params, key, filters[i].values[j]);
        }
    }
    return rc != 0 ? ENOMEM : 0;
}

static int collect_instance_set(const ec2_xml_span *set,
                                ec2_instance_list *out)
{
    const char *cursor = set->begin;
    while (cursor < set->end) {
        ec2_xml_span item;
        if (!ec2_xml_next(cursor, set->end, "item", &item, &cursor)) {
            break;
        }
        ec2_instance instance;
        if (!parse_instance(&item, &instance)) {
            continue;
        }
        int rc = instance_list_append(out, &instance);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static int parse_describe_response(const aws_resp *response,
                                   ec2_instance_list *out)
{
    if (response->body == NULL) {
        return EBADMSG;
    }
    ec2_xml_span document = {response->body, response->body + response->body_len};
    ec2_xml_span section;
    const char *next = NULL;

    if (ec2_xml_next(document.begin, document.end, "reservationSet", &section,
                     &next)) {
        const char *reservation = section.begin;
        while (reservation < section.end) {
            ec2_xml_span item;
            if (!ec2_xml_next(reservation, section.end, "item", &item,
                              &reservation)) {
                break;
            }
            ec2_xml_span instances;
            const char *instance_next = NULL;
            if (!ec2_xml_next(item.begin, item.end, "instancesSet", &instances,
                              &instance_next)) {
                continue;
            }
            int rc = collect_instance_set(&instances, out);
            if (rc != 0) {
                return rc;
            }
        }
        return 0;
    }

    if (ec2_xml_next(document.begin, document.end, "instancesSet", &section,
                     &next)) {
        return collect_instance_set(&section, out);
    }
    return EBADMSG;
}

int ec2_describe_instances(ec2_client *client, const ec2_filter *filters,
                           size_t filter_count, ec2_instance_list *out)
{
    if (client == NULL || out == NULL) {
        return EINVAL;
    }
    int rc = validate_filters(filters, filter_count);
    if (rc != 0) {
        return rc;
    }

    ec2_params params;
    ec2_params_init(&params);
    rc = build_describe_request(filters, filter_count, &params);
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "DescribeInstances", &params, &response);
        if (rc == 0) {
            ec2_instance_list parsed = {0};
            rc = parse_describe_response(&response, &parsed);
            if (rc == 0) {
                *out = parsed;
                parsed.items = NULL;
                parsed.count = 0;
            }
            ec2_instance_list_free(&parsed);
        }
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* TerminateInstances                                                        */
/* ------------------------------------------------------------------------- */

static int build_terminate_request(const char *const *instance_ids,
                                   size_t instance_id_count,
                                   ec2_params *params)
{
    int rc = 0;
    char key[64];

    rc |= ec2_params_add(params, "Action", "TerminateInstances");
    rc |= ec2_params_add(params, "Version", EC2_API_VERSION);
    for (size_t i = 0; i < instance_id_count; i++) {
        snprintf(key, sizeof(key), "InstanceId.%zu", i + 1);
        rc |= ec2_params_add(params, key, instance_ids[i]);
    }
    return rc != 0 ? ENOMEM : 0;
}

int ec2_terminate_instances(ec2_client *client, const char *const *instance_ids,
                            size_t instance_id_count,
                            ec2_terminate_result *out)
{
    if (client == NULL || out == NULL || instance_ids == NULL ||
        instance_id_count == 0) {
        return EINVAL;
    }
    for (size_t i = 0; i < instance_id_count; i++) {
        if (!nonempty(instance_ids[i])) {
            return EINVAL;
        }
    }

    ec2_params params;
    ec2_params_init(&params);
    int rc = build_terminate_request(instance_ids, instance_id_count, &params);
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "TerminateInstances", &params, &response);
        if (rc == 0) {
            rc = EBADMSG;
            if (response.body != NULL) {
                ec2_xml_span document = {response.body,
                                         response.body + response.body_len};
                ec2_xml_span set;
                const char *next = NULL;
                if (ec2_xml_next(document.begin, document.end, "instancesSet",
                                 &set, &next)) {
                    ec2_terminate_result parsed = {0};
                    rc = 0;
                    const char *cursor = set.begin;
                    while (cursor < set.end) {
                        ec2_xml_span item;
                        if (!ec2_xml_next(cursor, set.end, "item", &item,
                                          &cursor)) {
                            break;
                        }
                        ec2_terminate_entry *grown = realloc(
                            parsed.items,
                            (parsed.count + 1) * sizeof(*grown));
                        if (grown == NULL) {
                            rc = ENOMEM;
                            break;
                        }
                        parsed.items = grown;
                        ec2_terminate_entry *entry = &parsed.items[parsed.count];
                        memset(entry, 0, sizeof(*entry));
                        (void)ec2_xml_text(&item, "instanceId",
                                           entry->instance_id,
                                           sizeof(entry->instance_id));
                        ec2_xml_span state;
                        const char *state_next = NULL;
                        if (ec2_xml_next(item.begin, item.end, "currentState",
                                         &state, &state_next)) {
                            (void)ec2_xml_text(&state, "name", entry->state,
                                               sizeof(entry->state));
                        }
                        if (entry->instance_id[0] != '\0') {
                            parsed.count++;
                        }
                    }
                    if (rc == 0) {
                        *out = parsed;
                        parsed.items = NULL;
                        parsed.count = 0;
                    }
                    ec2_terminate_result_free(&parsed);
                }
            }
        }
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Waiters                                                                   */
/* ------------------------------------------------------------------------- */

typedef struct running_wait {
    ec2_client *client;
    const char *instance_id;
    ec2_instance last;
    int observed;
} running_wait;

static int running_poll(aws_ctx *aws, void *ud, int *done)
{
    (void)aws;
    running_wait *wait = ud;
    const char *values[] = {wait->instance_id};
    ec2_filter filter = {.name = "instance-id", .values = values, .value_count = 1};
    ec2_instance_list list = {0};

    *done = 0;
    int rc = ec2_describe_instances(wait->client, &filter, 1, &list);
    if (rc != 0) {
        return rc;
    }
    if (list.count > 0) {
        wait->last = list.items[0];
        wait->observed = 1;
        *done = strcmp(wait->last.state, "running") == 0 &&
                wait->last.public_ip[0] != '\0' &&
                strcmp(wait->last.public_ip, "0.0.0.0") != 0;
    }
    ec2_instance_list_free(&list);
    return 0;
}

int ec2_wait_running_with_public_ip(ec2_client *client, const char *instance_id,
                                    int attempts, int interval_sec,
                                    ec2_instance *out, int *timed_out)
{
    if (client == NULL || !nonempty(instance_id) || out == NULL ||
        timed_out == NULL) {
        return EINVAL;
    }

    running_wait wait = {.client = client, .instance_id = instance_id};
    int rc = aws_wait(client->aws, running_poll, &wait, attempts, interval_sec,
                      timed_out);
    if (rc != 0) {
        return rc;
    }
    if (wait.observed) {
        *out = wait.last;
    } else {
        memset(out, 0, sizeof(*out));
    }
    return 0;
}

typedef struct terminated_wait {
    ec2_client *client;
    const char *const *instance_ids;
    size_t instance_id_count;
} terminated_wait;

static int all_terminated(const terminated_wait *wait,
                          const ec2_instance_list *list)
{
    for (size_t i = 0; i < wait->instance_id_count; i++) {
        int satisfied = 1;
        for (size_t j = 0; j < list->count; j++) {
            if (strcmp(list->items[j].instance_id, wait->instance_ids[i]) != 0) {
                continue;
            }
            satisfied = strcmp(list->items[j].state, "terminated") == 0;
            break;
        }
        if (!satisfied) {
            return 0;
        }
    }
    return 1;
}

static int terminated_poll(aws_ctx *aws, void *ud, int *done)
{
    (void)aws;
    terminated_wait *wait = ud;
    ec2_filter filter = {
        .name = "instance-id",
        .values = wait->instance_ids,
        .value_count = wait->instance_id_count,
    };
    ec2_instance_list list = {0};

    *done = 0;
    int rc = ec2_describe_instances(wait->client, &filter, 1, &list);
    if (rc != 0) {
        return rc;
    }
    *done = all_terminated(wait, &list);
    ec2_instance_list_free(&list);
    return 0;
}

int ec2_wait_terminated(ec2_client *client, const char *const *instance_ids,
                        size_t instance_id_count, int attempts,
                        int interval_sec, int *timed_out)
{
    if (client == NULL || instance_ids == NULL || instance_id_count == 0 ||
        timed_out == NULL) {
        return EINVAL;
    }
    for (size_t i = 0; i < instance_id_count; i++) {
        if (!nonempty(instance_ids[i])) {
            return EINVAL;
        }
    }

    terminated_wait wait = {
        .client = client,
        .instance_ids = instance_ids,
        .instance_id_count = instance_id_count,
    };
    return aws_wait(client->aws, terminated_poll, &wait, attempts, interval_sec,
                    timed_out);
}
