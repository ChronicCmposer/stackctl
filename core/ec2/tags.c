/*
 * tags.c — CreateTags/DeleteTags. RunInstances carries its own
 * TagSpecifications; these operations support reconciliation and cleanup
 * (e.g. removing a launch-nonce tag).
 */

#include "ec2_internal.h"

#include <errno.h>
#include <stdio.h>

static int build_tag_request(const char *action, const char *const *instance_ids,
                             size_t instance_id_count, ec2_params *params)
{
    int rc = 0;
    char key[64];

    rc |= ec2_params_add(params, "Action", action);
    rc |= ec2_params_add(params, "Version", EC2_API_VERSION);
    for (size_t i = 0; i < instance_id_count; i++) {
        snprintf(key, sizeof(key), "ResourceId.%zu", i + 1);
        rc |= ec2_params_add(params, key, instance_ids[i]);
    }
    return rc != 0 ? ENOMEM : 0;
}

static int validate_ids(const char *const *instance_ids,
                        size_t instance_id_count)
{
    if (instance_ids == NULL || instance_id_count == 0) {
        return EINVAL;
    }
    for (size_t i = 0; i < instance_id_count; i++) {
        if (instance_ids[i] == NULL || instance_ids[i][0] == '\0') {
            return EINVAL;
        }
    }
    return 0;
}

int ec2_tag_instances(ec2_client *client, const char *const *instance_ids,
                      size_t instance_id_count, const ec2_tag *tags,
                      size_t tag_count)
{
    if (client == NULL || tags == NULL || tag_count == 0) {
        return EINVAL;
    }
    int rc = validate_ids(instance_ids, instance_id_count);
    if (rc != 0) {
        return rc;
    }
    for (size_t i = 0; i < tag_count; i++) {
        if (tags[i].key[0] == '\0') {
            return EINVAL;
        }
    }

    ec2_params params;
    ec2_params_init(&params);
    rc = build_tag_request("CreateTags", instance_ids, instance_id_count,
                           &params);
    char key[64];
    for (size_t i = 0; i < tag_count && rc == 0; i++) {
        snprintf(key, sizeof(key), "Tag.%zu.Key", i + 1);
        rc |= ec2_params_add(&params, key, tags[i].key);
        snprintf(key, sizeof(key), "Tag.%zu.Value", i + 1);
        rc |= ec2_params_add(&params, key, tags[i].value);
    }
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "CreateTags", &params, &response);
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}

int ec2_untag_instances(ec2_client *client, const char *const *instance_ids,
                        size_t instance_id_count, const char *const *tag_keys,
                        size_t tag_key_count)
{
    if (client == NULL || tag_keys == NULL || tag_key_count == 0) {
        return EINVAL;
    }
    int rc = validate_ids(instance_ids, instance_id_count);
    if (rc != 0) {
        return rc;
    }
    for (size_t i = 0; i < tag_key_count; i++) {
        if (tag_keys[i] == NULL || tag_keys[i][0] == '\0') {
            return EINVAL;
        }
    }

    ec2_params params;
    ec2_params_init(&params);
    rc = build_tag_request("DeleteTags", instance_ids, instance_id_count,
                           &params);
    char key[64];
    for (size_t i = 0; i < tag_key_count && rc == 0; i++) {
        snprintf(key, sizeof(key), "Tag.%zu.Key", i + 1);
        rc |= ec2_params_add(&params, key, tag_keys[i]);
    }
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "DeleteTags", &params, &response);
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}
