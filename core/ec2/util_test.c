/*
 * util_test.c — unit tests for the EC2 Query encoding/XML helpers.
 *
 * Pure unit tests, no transport: percent-encoding, form-body assembly,
 * depth-aware XML block iteration, entity decoding and base64 decoding
 * (EC2's GetConsoleOutput field) are pinned with fixed vectors.
 */

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

static void test_percent_encode(void)
{
    char *encoded = NULL;

    CHECK(ec2_percent_encode("abcXYZ019-_.~", &encoded) == 0,
          "encode unreserved returns 0");
    CHECK(encoded != NULL && strcmp(encoded, "abcXYZ019-_.~") == 0,
          "unreserved characters are not escaped");
    free(encoded);
    encoded = NULL;

    CHECK(ec2_percent_encode("team a/b:c+d", &encoded) == 0,
          "encode reserved returns 0");
    CHECK(encoded != NULL && strcmp(encoded, "team%20a%2Fb%3Ac%2Bd") == 0,
          "space and reserved characters are percent-encoded");
    free(encoded);
    encoded = NULL;

    CHECK(ec2_percent_encode("", &encoded) == 0, "encode empty returns 0");
    CHECK(encoded != NULL && encoded[0] == '\0', "empty input stays empty");
    free(encoded);
    encoded = NULL;

    CHECK(ec2_percent_encode("\xc3\xa9", &encoded) == 0, "encode UTF-8 returns 0");
    CHECK(encoded != NULL && strcmp(encoded, "%C3%A9") == 0,
          "non-ASCII bytes are percent-encoded");
    free(encoded);

    CHECK(ec2_percent_encode(NULL, &encoded) == EINVAL,
          "NULL input is EINVAL");
}

static void test_params_body(void)
{
    ec2_params params;
    const char *body = NULL;
    size_t length = 0;

    ec2_params_init(&params);
    CHECK(ec2_params_add(&params, "Action", "RunInstances") == 0,
          "add Action");
    CHECK(ec2_params_add(&params, "Version", EC2_API_VERSION) == 0,
          "add Version");
    CHECK(ec2_params_add(&params, "InstanceType", "g4dn.xlarge") == 0,
          "add instance type");
    CHECK(ec2_params_add_int(&params, "MinCount", 1) == 0, "add int");
    CHECK(ec2_params_done(&params, &body, &length) == 0, "finish body");
    if (body == NULL) {
        CHECK(0, "body is not NULL");
    } else {
        CHECK(length == strlen(body), "length matches the NUL-terminated body");
    }
    CHECK(strcmp(body, "Action=RunInstances&Version=" EC2_API_VERSION
                       "&InstanceType=g4dn.xlarge&MinCount=1") == 0,
          "form body is assembled in insertion order");
    ec2_params_free(&params);
}

static void test_xml_next_depth_aware(void)
{
    const char *doc =
        "<DescribeInstancesResponse><reservationSet>"
        "<item><instancesSet>"
        "<item><instanceId>i-1</instanceId><tagSet>"
        "<item><key>Project</key><value>proj</value></item>"
        "<item><key>Name</key><value>host</value></item>"
        "</tagSet></item>"
        "<item><instanceId>i-2</instanceId><tagSet>"
        "<item><key>Project</key><value>proj</value></item>"
        "</tagSet></item>"
        "</instancesSet></item>"
        "</reservationSet></DescribeInstancesResponse>";
    const char *doc_end = doc + strlen(doc);
    ec2_xml_span reservation;
    const char *cursor;
    ec2_xml_span instances;
    ec2_xml_span item;
    size_t items = 0;

    CHECK(ec2_xml_next(doc, doc_end, "reservationSet", &reservation, &cursor) == 1,
          "finds reservationSet");
    CHECK(ec2_xml_next(reservation.begin, reservation.end, "instancesSet",
                       &instances, &cursor) == 1,
          "finds instancesSet inside reservation");

    cursor = instances.begin;
    while (ec2_xml_next(cursor, instances.end, "item", &item, &cursor) == 1) {
        char id[64];
        items++;
        if (items == 1) {
            CHECK(ec2_xml_text(&item, "instanceId", id, sizeof id) == 1 &&
                      strcmp(id, "i-1") == 0,
                  "first top-level item is i-1");
        }
        if (items == 2) {
            CHECK(ec2_xml_text(&item, "instanceId", id, sizeof id) == 1 &&
                      strcmp(id, "i-2") == 0,
                  "nested tagSet items do not split the instance list");
        }
    }
    CHECK(items == 2, "exactly two top-level instance items");

    CHECK(ec2_xml_next(doc, doc_end, "absent", &item, &cursor) == 0,
          "absent tag returns 0");
}

static void test_xml_text_entities(void)
{
    const char *doc = "<item><value>a&amp;b&lt;c&gt;d&quot;e&#65;&#x42;</value>"
                      "<empty/>"
                      "<value>second</value></item>";
    ec2_xml_span span = {doc, doc + strlen(doc)};
    char out[128];

    CHECK(ec2_xml_text(&span, "value", out, sizeof out) == 1,
          "finds value element");
    CHECK(strcmp(out, "a&b<c>d\"eAB") == 0, "entities are decoded");
    CHECK(ec2_xml_text(&span, "empty", out, sizeof out) == 1 && out[0] == '\0',
          "self-closing element yields empty text");
    CHECK(ec2_xml_text(&span, "missing", out, sizeof out) == 0,
          "missing element returns 0");

    ec2_xml_decode("abcdef", 6, out, 4);
    CHECK(strcmp(out, "abc") == 0, "decode truncates safely");
}

static void test_base64(void)
{
    char *decoded = NULL;

    CHECK(ec2_base64_decode("aGVsbG8=", 8, &decoded) == 0, "decode hello");
    CHECK(decoded != NULL && strcmp(decoded, "hello") == 0,
          "base64 decodes to hello");
    free(decoded);
    decoded = NULL;

    CHECK(ec2_base64_decode("aGVs\n bG8=", 10, &decoded) == 0,
          "newlines/spaces inside base64 are ignored");
    CHECK(decoded != NULL && strcmp(decoded, "hello") == 0,
          "whitespace-tolerant decode matches");
    free(decoded);
    decoded = NULL;

    CHECK(ec2_base64_decode("!!!!", 4, &decoded) == EINVAL,
          "invalid base64 is EINVAL");
    CHECK(decoded == NULL, "invalid base64 leaves out untouched");

    CHECK(ec2_base64_decode("", 0, &decoded) == 0, "empty input decodes");
    CHECK(decoded != NULL && decoded[0] == '\0', "empty decode is empty string");
    free(decoded);
}

int main(void)
{
    test_percent_encode();
    test_params_body();
    test_xml_next_depth_aware();
    test_xml_text_entities();
    test_base64();

    if (failures != 0) {
        fprintf(stderr, "%d util test(s) failed\n", failures);
        return 1;
    }
    printf("util_test: all tests passed\n");
    return 0;
}
