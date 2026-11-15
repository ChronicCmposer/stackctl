/*
 * images.c — DescribeImages (spec §4 AMI-region preflight: the effective AMI
 * must resolve in the client region, under every AMI_POLICY).
 */

#include "ec2_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int build_describe_images_request(const char *const *image_ids,
                                         size_t image_id_count,
                                         ec2_params *params)
{
    int rc = 0;
    char key[64];

    rc |= ec2_params_add(params, "Action", "DescribeImages");
    rc |= ec2_params_add(params, "Version", EC2_API_VERSION);
    for (size_t i = 0; i < image_id_count; i++) {
        snprintf(key, sizeof(key), "ImageId.%zu", i + 1);
        rc |= ec2_params_add(params, key, image_ids[i]);
    }
    return rc != 0 ? ENOMEM : 0;
}

static int parse_images_response(const aws_resp *response, ec2_image_list *out)
{
    if (response->body == NULL) {
        return EBADMSG;
    }
    ec2_xml_span document = {response->body, response->body + response->body_len};
    ec2_xml_span set;
    const char *next = NULL;
    if (!ec2_xml_next(document.begin, document.end, "imagesSet", &set, &next)) {
        return EBADMSG;
    }

    const char *cursor = set.begin;
    while (cursor < set.end) {
        ec2_xml_span item;
        if (!ec2_xml_next(cursor, set.end, "item", &item, &cursor)) {
            break;
        }
        ec2_image image;
        memset(&image, 0, sizeof(image));
        (void)ec2_xml_text(&item, "imageId", image.image_id,
                           sizeof(image.image_id));
        (void)ec2_xml_text(&item, "imageState", image.state,
                           sizeof(image.state));
        (void)ec2_xml_text(&item, "name", image.name, sizeof(image.name));
        (void)ec2_xml_text(&item, "architecture", image.architecture,
                           sizeof(image.architecture));
        (void)ec2_xml_text(&item, "rootDeviceName", image.root_device_name,
                           sizeof(image.root_device_name));
        if (image.image_id[0] == '\0') {
            continue;
        }

        ec2_image *grown =
            realloc(out->items, (out->count + 1) * sizeof(*grown));
        if (grown == NULL) {
            return ENOMEM;
        }
        out->items = grown;
        out->items[out->count] = image;
        out->count++;
    }
    return 0;
}

int ec2_describe_images(ec2_client *client, const char *const *image_ids,
                        size_t image_id_count, ec2_image_list *out)
{
    if (client == NULL || out == NULL || image_ids == NULL ||
        image_id_count == 0) {
        return EINVAL;
    }
    for (size_t i = 0; i < image_id_count; i++) {
        if (image_ids[i] == NULL || image_ids[i][0] == '\0') {
            return EINVAL;
        }
    }

    ec2_params params;
    ec2_params_init(&params);
    int rc = build_describe_images_request(image_ids, image_id_count, &params);
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "DescribeImages", &params, &response);
        if (rc == 0) {
            ec2_image_list parsed = {0};
            rc = parse_images_response(&response, &parsed);
            if (rc == 0) {
                *out = parsed;
                parsed.items = NULL;
                parsed.count = 0;
            }
            ec2_image_list_free(&parsed);
        }
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}
