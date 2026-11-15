/*
 * cli_identity_test.c — C1 identity guard + signal-consumed bookkeeping.
 *
 * Drives cli_assert_operator_identity through the core/iam fake transport so no
 * network or credentials are needed. Asserts the suffix match, the dedicated
 * assumed-role rejection, the STS-failure mapping, and the consumed flag.
 */

#include "cli.h"
#include "iam.h"
#include "iam_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* --- fake transport ----------------------------------------------------- */

typedef struct fake_transport {
    long status;
    const char *body;
    int fail_with;
    int calls;
} fake_transport;

static int fake_send(aws_ctx *aws, const aws_req *req, aws_resp *resp, void *ud) {
    fake_transport *fake = ud;

    (void)aws;
    (void)req;
    fake->calls++;
    if (fake->fail_with != 0) {
        return fake->fail_with;
    }
    resp->status = fake->status;
    if (fake->body != NULL) {
        size_t length = strlen(fake->body);

        resp->body = malloc(length + 1);
        if (resp->body == NULL) {
            return ENOMEM;
        }
        memcpy(resp->body, fake->body, length + 1);
        resp->body_len = length;
    }
    return 0;
}

/* aws_ctx is opaque and never dereferenced by the fake transport. */
static char fake_aws_storage;

static aws_ctx *fake_ctx(void) { return (aws_ctx *)&fake_aws_storage; }

/* --- stderr capture ----------------------------------------------------- */

static int saved_stderr = -1;
static FILE *capture_file;

static void capture_begin(void) {
    fflush(stderr);
    capture_file = tmpfile();
    saved_stderr = dup(fileno(stderr));
    if (capture_file != NULL && saved_stderr >= 0) {
        dup2(fileno(capture_file), fileno(stderr));
    }
}

static void capture_end(char *out, size_t size) {
    fflush(stderr);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, fileno(stderr));
        close(saved_stderr);
        saved_stderr = -1;
    }
    out[0] = '\0';
    if (capture_file != NULL) {
        size_t got;

        rewind(capture_file);
        got = fread(out, 1, size - 1, capture_file);
        out[got] = '\0';
        fclose(capture_file);
        capture_file = NULL;
    }
}

static const char ARN_XML_TEMPLATE[] =
    "<GetCallerIdentityResponse "
    "xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
    "<GetCallerIdentityResult>"
    "<Arn>%s</Arn>"
    "<UserId>AIDAEXAMPLEUSERID</UserId>"
    "<Account>123456789012</Account>"
    "</GetCallerIdentityResult>"
    "</GetCallerIdentityResponse>";

static char *identity_xml(const char *arn) {
    size_t need = strlen(ARN_XML_TEMPLATE) + strlen(arn) + 1;
    char *xml = malloc(need);

    if (xml != NULL) {
        snprintf(xml, need, ARN_XML_TEMPLATE, arn);
    }
    return xml;
}

static int run_guard(const char *arn, int fail_with, char *stderr_out,
                     size_t stderr_cap) {
    fake_transport fake = {.status = 200, .fail_with = fail_with};
    char *xml = arn != NULL ? identity_xml(arn) : NULL;
    int rc;

    fake.body = xml;
    iam_test_set_transport(fake_send, &fake);
    capture_begin();
    rc = cli_assert_operator_identity(fake_ctx(), "demo");
    capture_end(stderr_out, stderr_cap);
    iam_test_set_transport(NULL, NULL);
    free(xml);
    CHECK(fake.calls == 1, "one STS call");
    return rc;
}

/* --- cases -------------------------------------------------------------- */

static void test_matching_arn_proceeds(void) {
    char err[1024];
    int rc = run_guard("arn:aws:iam::123456789012:user/demo", 0, err,
                       sizeof err);

    CHECK(rc == CLI_EXIT_OK, "matching ARN returns 0");
}

static void test_suffix_mismatch_aborts_verify(void) {
    char err[1024];
    int rc = run_guard("arn:aws:iam::123456789012:user/other", 0, err,
                       sizeof err);

    CHECK(rc == CLI_EXIT_VERIFY, "suffix mismatch returns 3");
    CHECK(strstr(err, "does not end with") != NULL,
          "mismatch diagnostic names the expected suffix");
    CHECK(strstr(err, ":user/demo") != NULL,
          "mismatch diagnostic names the project user");
}

static void test_assumed_role_has_dedicated_message(void) {
    char err[1024];
    int rc = run_guard("arn:aws:sts::123456789012:assumed-role/admin/session",
                       0, err, sizeof err);

    CHECK(rc == CLI_EXIT_VERIFY, "assumed role returns 3");
    CHECK(strstr(err, "assumed role") != NULL,
          "assumed-role diagnostic is dedicated");
}

static void test_sts_failure_is_aws_exit(void) {
    char err[1024];
    int rc = run_guard(NULL, EIO, err, sizeof err);

    CHECK(rc == CLI_EXIT_AWS, "STS failure returns 2");
    CHECK(strstr(err, "cannot verify the caller identity") != NULL,
          "STS failure diagnostic");
}

static void test_signal_consumed_flag(void) {
    cli_signal_test_reset();
    CHECK(cli_signal_consumed() == 0, "not consumed initially");
    cli_signal_mark_consumed();
    CHECK(cli_signal_consumed() == 1, "consumed after mark");
    cli_signal_test_reset();
    CHECK(cli_signal_consumed() == 0, "reset clears consumed");
}

int main(void) {
    test_matching_arn_proceeds();
    test_suffix_mismatch_aborts_verify();
    test_assumed_role_has_dedicated_message();
    test_sts_failure_is_aws_exit();
    test_signal_consumed_flag();

    if (failures != 0) {
        fprintf(stderr, "%d cli_identity test check(s) failed\n", failures);
        return 1;
    }
    printf("cli_identity_test: all checks passed\n");
    return 0;
}
