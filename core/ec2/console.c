/*
 * console.c — GetConsoleOutput for host-key fingerprint verification
 * (spec §4 launch: the cloud-init "BEGIN SSH HOST KEY FINGERPRINTS" block).
 */

#include "ec2_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int ec2_get_console_output(ec2_client *client, const char *instance_id,
                           char **output_out)
{
    if (client == NULL || output_out == NULL || instance_id == NULL ||
        instance_id[0] == '\0') {
        return EINVAL;
    }

    ec2_params params;
    ec2_params_init(&params);
    int rc = ec2_params_add(&params, "Action", "GetConsoleOutput");
    rc |= ec2_params_add(&params, "Version", EC2_API_VERSION);
    rc |= ec2_params_add(&params, "InstanceId", instance_id);
    rc |= ec2_params_add(&params, "Latest", "true");
    if (rc == 0) {
        aws_resp response = {0};
        rc = ec2_call(client, "GetConsoleOutput", &params, &response);
        if (rc == 0) {
            rc = EBADMSG;
            if (response.body != NULL) {
                ec2_xml_span document = {response.body,
                                         response.body + response.body_len};
                ec2_xml_span output;
                const char *next = NULL;
                if (ec2_xml_next(document.begin, document.end, "output",
                                 &output, &next)) {
                    rc = 0;
                    if (output.begin != output.end) {
                        rc = ec2_base64_decode(
                            output.begin,
                            (size_t)(output.end - output.begin), output_out);
                    } else {
                        *output_out = NULL;
                    }
                }
            }
        }
        aws_resp_free(&response);
    }
    ec2_params_free(&params);
    return rc;
}
