/*
 * iam_test.c — fake-transport tests for core/iam (CONTRACT Amendment 6).
 *
 * No network: a fake transport captures the exact aws_req (service, region,
 * method, path, content type, form body) and replays canned XML/error
 * responses. Tests pin request encoding (Action/Version/params and escaping),
 * Marker/IsTruncated pagination, response parsing, error mapping,
 * out-params-untouched-on-failure, free safety, and that no secret reaches
 * stderr (CONTRACT Amendment 2/4).
 */

#include "iam.h"
#include "iam_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond)                                                            \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                      \
    } while (0)

#define CHECK_STR(actual, expected)                                            \
    do {                                                                       \
        checks++;                                                              \
        const char *a_ = (actual);                                             \
        const char *e_ = (expected);                                           \
        if (a_ == NULL || strcmp(a_, e_) != 0) {                               \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: '%s' != '%s'\n", __FILE__, __LINE__,  \
                    a_ != NULL ? a_ : "(null)", e_);                           \
        }                                                                      \
    } while (0)

#define CHECK_INT(actual, expected)                                            \
    do {                                                                       \
        checks++;                                                              \
        long a_ = (long)(actual);                                              \
        long e_ = (long)(expected);                                            \
        if (a_ != e_) {                                                        \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %ld != %ld\n", __FILE__, __LINE__, a_, \
                    e_);                                                       \
        }                                                                      \
    } while (0)

/* --- fake transport ----------------------------------------------------- */

#define SCRIPT_MAX 16

typedef struct fake_step {
    long status;
    const char *body;
} fake_step;

typedef struct fake_transport {
    fake_step steps[SCRIPT_MAX];
    size_t step_count;
    size_t step_index;
    int fail_with;
    size_t call_count;

    char service[32];
    char region[32];
    char method[16];
    char path[16];
    char content_type[64];
    char body[8192];
    int unsigned_payload;
} fake_transport;

static void fake_reset(fake_transport *fake)
{
    memset(fake, 0, sizeof(*fake));
}

static void fake_queue(fake_transport *fake, long status, const char *body)
{
    if (fake->step_count >= SCRIPT_MAX) {
        return;
    }
    fake->steps[fake->step_count].status = status;
    fake->steps[fake->step_count].body = body;
    fake->step_count++;
}

static int fake_send(aws_ctx *aws, const aws_req *req, aws_resp *resp, void *ud)
{
    (void)aws;
    fake_transport *fake = ud;

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
    fake->unsigned_payload = req->unsigned_payload;
    if (req->body != NULL) {
        size_t length = req->body_len;
        if (length >= sizeof fake->body) {
            length = sizeof fake->body - 1;
        }
        memcpy(fake->body, req->body, length);
        fake->body[length] = '\0';
    } else {
        fake->body[0] = '\0';
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
        size_t length = strlen(step->body);
        resp->body = malloc(length + 1);
        if (resp->body == NULL) {
            return ENOMEM;
        }
        memcpy(resp->body, step->body, length + 1);
        resp->body_len = length;
    }
    return 0;
}

/* aws_ctx is opaque and never dereferenced by the fake transport. */
static char fake_aws_storage;

static aws_ctx *fake_ctx(void)
{
    return (aws_ctx *)&fake_aws_storage;
}

static void install(fake_transport *fake)
{
    fake_reset(fake);
    iam_test_set_transport(fake_send, fake);
}

static void uninstall(void)
{
    iam_test_set_transport(NULL, NULL);
}

static int body_has(const fake_transport *fake, const char *needle)
{
    return strstr(fake->body, needle) != NULL;
}

/* --- stderr capture ----------------------------------------------------- */

static int saved_stderr = -1;
static FILE *capture_file;

static void capture_begin(void)
{
    fflush(stderr);
    capture_file = tmpfile();
    saved_stderr = dup(fileno(stderr));
    if (capture_file != NULL && saved_stderr >= 0) {
        dup2(fileno(capture_file), fileno(stderr));
    }
}

static void capture_end(char *out, size_t size)
{
    fflush(stderr);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, fileno(stderr));
        close(saved_stderr);
        saved_stderr = -1;
    }
    out[0] = '\0';
    if (capture_file != NULL) {
        rewind(capture_file);
        size_t read = fread(out, 1, size - 1, capture_file);
        out[read] = '\0';
        fclose(capture_file);
        capture_file = NULL;
    }
}

/* --- fixtures ----------------------------------------------------------- */

static const char IDENTITY_XML[] =
    "<GetCallerIdentityResponse "
    "xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
    "<GetCallerIdentityResult>"
    "<Arn>arn:aws:iam::123456789012:user/demo</Arn>"
    "<UserId>AIDAEXAMPLEUSERID</UserId>"
    "<Account>123456789012</Account>"
    "</GetCallerIdentityResult>"
    "<ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>"
    "</GetCallerIdentityResponse>";

static const char TWO_KEYS_XML[] =
    "<ListAccessKeysResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"
    "<ListAccessKeysResult>"
    "<AccessKeyMetadata>"
    "<member>"
    "<UserName>demo</UserName>"
    "<AccessKeyId>AKIAONE</AccessKeyId>"
    "<Status>Active</Status>"
    "<CreateDate>2026-01-02T03:04:05Z</CreateDate>"
    "</member>"
    "<member>"
    "<UserName>demo</UserName>"
    "<AccessKeyId>AKIATWO</AccessKeyId>"
    "<Status>Inactive</Status>"
    "<CreateDate>2026-02-03T04:05:06Z</CreateDate>"
    "</member>"
    "</AccessKeyMetadata>"
    "<IsTruncated>false</IsTruncated>"
    "</ListAccessKeysResult>"
    "<ResponseMetadata><RequestId>req-2</RequestId></ResponseMetadata>"
    "</ListAccessKeysResponse>";

static const char PAGE_ONE_XML[] =
    "<ListAccessKeysResponse><ListAccessKeysResult>"
    "<AccessKeyMetadata><member>"
    "<UserName>demo</UserName><AccessKeyId>AKIAPAGE1</AccessKeyId>"
    "<Status>Active</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate>"
    "</member></AccessKeyMetadata>"
    "<IsTruncated>true</IsTruncated>"
    "<Marker>M1+/=</Marker>"
    "</ListAccessKeysResult></ListAccessKeysResponse>";

static const char PAGE_TWO_XML[] =
    "<ListAccessKeysResponse><ListAccessKeysResult>"
    "<AccessKeyMetadata><member>"
    "<UserName>demo</UserName><AccessKeyId>AKIAPAGE2</AccessKeyId>"
    "<Status>Active</Status><CreateDate>2026-01-02T00:00:00Z</CreateDate>"
    "</member></AccessKeyMetadata>"
    "<IsTruncated>false</IsTruncated>"
    "</ListAccessKeysResult></ListAccessKeysResponse>";

static const char CREATE_XML[] =
    "<CreateAccessKeyResponse "
    "xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"
    "<CreateAccessKeyResult><AccessKey>"
    "<UserName>demo</UserName>"
    "<AccessKeyId>AKIANEW</AccessKeyId>"
    "<Status>Active</Status>"
    "<SecretAccessKey>SECRETVALUE123</SecretAccessKey>"
    "<CreateDate>2026-03-04T05:06:07Z</CreateDate>"
    "</AccessKey></CreateAccessKeyResult>"
    "<ResponseMetadata><RequestId>req-3</RequestId></ResponseMetadata>"
    "</CreateAccessKeyResponse>";

static const char DELETE_XML[] =
    "<DeleteAccessKeyResponse "
    "xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"
    "<ResponseMetadata><RequestId>req-4</RequestId></ResponseMetadata>"
    "</DeleteAccessKeyResponse>";

static const char NO_SUCH_ENTITY_XML[] =
    "<ErrorResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">"
    "<Error><Type>Sender</Type><Code>NoSuchEntity</Code>"
    "<Message>The user does not exist.</Message></Error>"
    "<RequestId>req-5</RequestId></ErrorResponse>";

/* --- tests -------------------------------------------------------------- */

static void test_get_caller_identity(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, IDENTITY_XML);

    char *account = NULL;
    char *arn = NULL;
    char *user_id = NULL;
    int rc = iam_get_caller_identity(fake_ctx(), &account, &arn, &user_id);

    CHECK_INT(rc, 0);
    CHECK_STR(account, "123456789012");
    CHECK_STR(arn, "arn:aws:iam::123456789012:user/demo");
    CHECK_STR(user_id, "AIDAEXAMPLEUSERID");
    CHECK_STR(fake.service, "sts");
    CHECK_STR(fake.region, "us-east-1");
    CHECK_STR(fake.method, "POST");
    CHECK_STR(fake.path, "/");
    CHECK_STR(fake.content_type, "application/x-www-form-urlencoded");
    CHECK_INT(fake.unsigned_payload, 0);
    CHECK(body_has(&fake, "Action=GetCallerIdentity"));
    CHECK(body_has(&fake, "Version=2011-06-15"));

    free(account);
    free(arn);
    free(user_id);
    uninstall();
}

static void test_list_access_keys_own_user(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, TWO_KEYS_XML);

    iam_key *keys = NULL;
    size_t count = 0;
    int rc = iam_list_access_keys(fake_ctx(), NULL, &keys, &count);

    CHECK_INT(rc, 0);
    CHECK_INT(count, 2);
    CHECK(keys != NULL);
    if (keys != NULL && count == 2) {
        CHECK_STR(keys[0].user_name, "demo");
        CHECK_STR(keys[0].access_key_id, "AKIAONE");
        CHECK_STR(keys[0].status, "Active");
        CHECK_STR(keys[0].create_date, "2026-01-02T03:04:05Z");
        CHECK(keys[0].secret_access_key == NULL);
        CHECK_STR(keys[1].access_key_id, "AKIATWO");
        CHECK_STR(keys[1].status, "Inactive");
    }
    CHECK_STR(fake.service, "iam");
    CHECK_STR(fake.region, "us-east-1");
    CHECK(body_has(&fake, "Action=ListAccessKeys"));
    CHECK(body_has(&fake, "Version=2010-05-08"));
    CHECK(!body_has(&fake, "UserName="));

    iam_keys_free(keys, count);
    uninstall();
}

static void test_list_access_keys_escapes_user_name(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, TWO_KEYS_XML);

    iam_key *keys = NULL;
    size_t count = 0;
    int rc = iam_list_access_keys(fake_ctx(), "alice@example.com/+ x", &keys,
                                  &count);

    CHECK_INT(rc, 0);
    CHECK(body_has(&fake, "UserName=alice%40example.com%2F%2B%20x"));

    iam_keys_free(keys, count);
    uninstall();
}

static void test_list_access_keys_paginates(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, PAGE_ONE_XML);
    fake_queue(&fake, 200, PAGE_TWO_XML);

    iam_key *keys = NULL;
    size_t count = 0;
    int rc = iam_list_access_keys(fake_ctx(), "demo", &keys, &count);

    CHECK_INT(rc, 0);
    CHECK_INT(count, 2);
    CHECK_INT(fake.call_count, 2);
    CHECK_STR(fake.body, "Action=ListAccessKeys&Version=2010-05-08&"
                         "UserName=demo&Marker=M1%2B%2F%3D");
    if (keys != NULL && count == 2) {
        CHECK_STR(keys[0].access_key_id, "AKIAPAGE1");
        CHECK_STR(keys[1].access_key_id, "AKIAPAGE2");
    }

    iam_keys_free(keys, count);
    uninstall();
}

static void test_create_access_key(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, CREATE_XML);

    iam_key key = {0};
    int rc = iam_create_access_key(fake_ctx(), "demo", &key);

    CHECK_INT(rc, 0);
    CHECK_STR(key.user_name, "demo");
    CHECK_STR(key.access_key_id, "AKIANEW");
    CHECK_STR(key.status, "Active");
    CHECK_STR(key.create_date, "2026-03-04T05:06:07Z");
    CHECK_STR(key.secret_access_key, "SECRETVALUE123");
    CHECK(body_has(&fake, "Action=CreateAccessKey"));
    CHECK(body_has(&fake, "Version=2010-05-08"));
    CHECK(body_has(&fake, "UserName=demo"));

    iam_key_free(&key);
    uninstall();
}

static void test_create_access_key_secret_not_on_stderr(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, CREATE_XML);

    iam_key key = {0};
    char stderr_text[4096];
    capture_begin();
    int rc = iam_create_access_key(fake_ctx(), NULL, &key);
    capture_end(stderr_text, sizeof stderr_text);

    CHECK_INT(rc, 0);
    CHECK(strstr(stderr_text, "SECRETVALUE123") == NULL);
    CHECK(!body_has(&fake, "UserName="));

    iam_key_free(&key);
    uninstall();
}

static void test_delete_access_key(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 200, DELETE_XML);

    int rc = iam_delete_access_key(fake_ctx(), "demo", "AKIA/DEL+=");

    CHECK_INT(rc, 0);
    CHECK(body_has(&fake, "Action=DeleteAccessKey"));
    CHECK(body_has(&fake, "Version=2010-05-08"));
    CHECK(body_has(&fake, "UserName=demo"));
    CHECK(body_has(&fake, "AccessKeyId=AKIA%2FDEL%2B%3D"));
    uninstall();
}

static void test_aws_error_maps_and_reports(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 404, NO_SUCH_ENTITY_XML);

    iam_key *keys = (iam_key *)0xdeadbeef;
    size_t count = 42;
    char stderr_text[4096];
    capture_begin();
    int rc = iam_list_access_keys(fake_ctx(), "demo", &keys, &count);
    capture_end(stderr_text, sizeof stderr_text);

    CHECK_INT(rc, ENOENT);
    CHECK(keys == (iam_key *)0xdeadbeef);
    CHECK_INT(count, 42);
    CHECK(strstr(stderr_text, "NoSuchEntity") != NULL);
    CHECK(strstr(stderr_text, "The user does not exist.") != NULL);
    uninstall();
}

static void test_transport_failure_leaves_out_untouched(void)
{
    fake_transport fake;
    install(&fake);
    fake.fail_with = ETIMEDOUT;

    char *account = (char *)0x1;
    char *arn = (char *)0x2;
    char *user_id = (char *)0x3;
    int rc = iam_get_caller_identity(fake_ctx(), &account, &arn, &user_id);

    CHECK_INT(rc, ETIMEDOUT);
    CHECK(account == (char *)0x1);
    CHECK(arn == (char *)0x2);
    CHECK(user_id == (char *)0x3);
    uninstall();
}

static void test_create_failure_leaves_out_untouched(void)
{
    fake_transport fake;
    install(&fake);
    fake_queue(&fake, 403, NO_SUCH_ENTITY_XML);

    iam_key key = {0};
    int rc = iam_create_access_key(fake_ctx(), "demo", &key);

    CHECK(rc != 0);
    CHECK(key.user_name == NULL);
    CHECK(key.access_key_id == NULL);
    CHECK(key.secret_access_key == NULL);
    CHECK(key.status == NULL);
    CHECK(key.create_date == NULL);
    uninstall();
}

static void test_free_safety(void)
{
    iam_key key = {0};
    iam_key_free(&key);
    iam_key_free(NULL);
    iam_keys_free(NULL, 0);

    iam_key *keys = calloc(2, sizeof(*keys));
    if (keys != NULL) {
        keys[0].access_key_id = strdup("AKIAONE");
        keys[1].secret_access_key = strdup("SECRET");
        iam_keys_free(keys, 2);
    }
    CHECK(1);
}

static void test_invalid_arguments(void)
{
    iam_key *keys = NULL;
    size_t count = 0;
    CHECK_INT(iam_get_caller_identity(NULL, NULL, NULL, NULL), EINVAL);
    CHECK_INT(iam_list_access_keys(NULL, NULL, &keys, &count), EINVAL);
    CHECK_INT(iam_list_access_keys(fake_ctx(), NULL, NULL, &count), EINVAL);
    CHECK_INT(iam_create_access_key(fake_ctx(), NULL, NULL), EINVAL);
    CHECK_INT(iam_delete_access_key(fake_ctx(), NULL, NULL), EINVAL);
}

int main(void)
{
    test_get_caller_identity();
    test_list_access_keys_own_user();
    test_list_access_keys_escapes_user_name();
    test_list_access_keys_paginates();
    test_create_access_key();
    test_create_access_key_secret_not_on_stderr();
    test_delete_access_key();
    test_aws_error_maps_and_reports();
    test_transport_failure_leaves_out_untouched();
    test_create_failure_leaves_out_untouched();
    test_free_safety();
    test_invalid_arguments();

    if (failures != 0) {
        fprintf(stderr, "%d/%d checks failed\n", failures, checks);
        return 1;
    }
    printf("iam_test: %d checks passed\n", checks);
    return 0;
}
