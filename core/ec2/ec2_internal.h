/*
 * ec2_internal.h — unit-test seams and shared helpers for core/ec2.
 *
 * NOT part of the frozen public surface (ec2.h). Tests include this header to
 * inject a fake transport and to exercise the XML/encoding helpers directly.
 */

#ifndef STACKCTL_CORE_EC2_EC2_INTERNAL_H
#define STACKCTL_CORE_EC2_EC2_INTERNAL_H

#include <stddef.h>

#include "ec2.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EC2 Query API version carried by every request. */
#define EC2_API_VERSION "2016-11-15"

/* Capacity of the client region field. */
#define EC2_REGION_MAX 64

/*
 * Transport seam: performs one signed request. The production adapter forwards
 * to aws_request(); tests replace it with a canned-response fake. Returning a
 * non-zero code aborts the operation with that code; an HTTP response (whatever
 * its status) returns 0 with `resp` populated.
 */
typedef int (*ec2_transport_fn)(aws_ctx *aws, const aws_req *req,
                                aws_resp *resp, void *ud);

struct ec2_client {
    aws_ctx *aws;
    char region[EC2_REGION_MAX];
    ec2_transport_fn transport;
    void *transport_ud;
};

/* Growable form body: "Action=...&Version=..." plus appended parameters. */
typedef struct ec2_params {
    char *body;
    size_t length;
    size_t capacity;
    int oom;
} ec2_params;

void ec2_params_init(ec2_params *params);
void ec2_params_free(ec2_params *params);

/*
 * Append one `&<name>=<percent-encoded value>` pair. Returns 0, or ENOMEM
 * (subsequent calls become no-ops and ec2_params_done() reports the error).
 */
int ec2_params_add(ec2_params *params, const char *name, const char *value);

/*
 * Append an unencoded integer parameter (no percent-encoding needed).
 */
int ec2_params_add_int(ec2_params *params, const char *name, long value);

/*
 * Finish the body: NUL-terminate it and return the buffer/length. Ownership
 * stays with `params` until ec2_params_free(). Returns non-zero on OOM.
 */
int ec2_params_done(ec2_params *params, const char **body, size_t *length);

/* Percent-encode `value` per RFC 3986 (unreserved: A-Z a-z 0-9 - _ . ~). */
int ec2_percent_encode(const char *value, char **out);

/* A substring span inside a response document. */
typedef struct ec2_xml_span {
    const char *begin;
    const char *end;
} ec2_xml_span;

/*
 * Find the next `<tag ...> ... </tag>` block after `cursor` inside [cursor,
 * doc_end), honouring nesting of same-named tags. On success writes the inner
 * content span and the position just past the closing tag to `next_cursor`.
 * Returns 1 when found, 0 when not.
 */
int ec2_xml_next(const char *cursor, const char *doc_end, const char *tag,
                 ec2_xml_span *inner, const char **next_cursor);

/*
 * Copy the text of the first `<tag>` element inside `span` into `out`,
 * entity-decoding it. Returns 1 when found, 0 when absent. Truncates safely.
 */
int ec2_xml_text(const ec2_xml_span *span, const char *tag, char *out,
                 size_t out_size);

/* Entity-decode `length` bytes at `text` into `out` (NUL-terminated). */
void ec2_xml_decode(const char *text, size_t length, char *out,
                    size_t out_size);

/*
 * Decode standard base64 into a heap-allocated NUL-terminated string. White
 * space is ignored; invalid input yields EINVAL. Returns 0 or an errno code.
 */
int ec2_base64_decode(const char *input, size_t input_length, char **out);

/*
 * Issue `action` with `params` (which already contains Action/Version). On an
 * HTTP error response this reports the AWS error to stderr and returns
 * EC2_ERR_AWS_API. On success `resp` is populated and owned by the caller.
 */
int ec2_call(ec2_client *client, const char *action, ec2_params *params,
             aws_resp *resp);

/*
 * Report an AWS error document for `action` on stderr with the spec §4 hints
 * (capacity rejections, UnauthorizedOperation) and return EC2_ERR_AWS_API.
 */
int ec2_report_api_error(const char *action, aws_resp *resp);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CORE_EC2_EC2_INTERNAL_H */
