/*
 * s3_test.c — unit tests for core/s3 over a fake transport.
 *
 * Every public function is exercised against the fake: tests assert the exact
 * method, path, query, payload-signing flag and content type of the outgoing
 * request, and the parsed result / mapped error of the response. No socket is
 * ever opened.
 */

#include "s3.h"
#include "s3_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct fake_transport {
    int calls;
    int transport_rc;
    char method[16];
    char path[2048];
    char query[2048];
    int has_query;
    char content_type[128];
    int has_content_type;
    int unsigned_payload;
    char *body;
    size_t body_len;

    long status;
    const char *reply_body;
    const char *etag;
    const char *content_length;
} fake_transport;

static void fake_reset(fake_transport *f)
{
    free(f->body);
    memset(f, 0, sizeof(*f));
    f->status = 200;
}

static void add_header(aws_resp *resp, const char *name, const char *value)
{
    if (value == NULL) {
        return;
    }
    aws_header *grown =
        realloc(resp->headers, (resp->header_count + 1) * sizeof(*grown));
    if (grown == NULL) {
        return;
    }
    resp->headers = grown;
    aws_header *slot = &resp->headers[resp->header_count];
    slot->name = strdup(name);
    slot->value = strdup(value);
    if (slot->name == NULL || slot->value == NULL) {
        free(slot->name);
        free(slot->value);
        return;
    }
    resp->header_count++;
}

static int fake_send(void *ud, const aws_req *req, aws_resp *resp)
{
    fake_transport *f = ud;
    f->calls++;
    snprintf(f->method, sizeof(f->method), "%s", req->method);
    snprintf(f->path, sizeof(f->path), "%s", req->path);
    if (req->query != NULL) {
        snprintf(f->query, sizeof(f->query), "%s", req->query);
        f->has_query = req->query[0] != '\0';
    }
    if (req->content_type != NULL) {
        snprintf(f->content_type, sizeof(f->content_type), "%s",
                 req->content_type);
        f->has_content_type = 1;
    }
    f->unsigned_payload = req->unsigned_payload;
    free(f->body);
    f->body = NULL;
    f->body_len = req->body_len;
    if (req->body != NULL && req->body_len > 0) {
        f->body = malloc(req->body_len);
        if (f->body != NULL) {
            memcpy(f->body, req->body, req->body_len);
        }
    }

    if (f->transport_rc != 0) {
        return f->transport_rc;
    }

    resp->status = f->status;
    if (f->reply_body != NULL) {
        resp->body_len = strlen(f->reply_body);
        resp->body = malloc(resp->body_len + 1);
        if (resp->body != NULL) {
            memcpy(resp->body, f->reply_body, resp->body_len + 1);
        }
    }
    add_header(resp, "ETag", f->etag);
    add_header(resp, "Content-Length", f->content_length);
    add_header(resp, "Date", "Mon, 02 Jan 2006 15:04:05 GMT");
    return 0;
}

static s3_client *client_for(fake_transport *f)
{
    s3_client *client = NULL;
    int rc = s3_client_init_with_transport(&client, "us-east-1", fake_send, f);
    CHECK(rc == 0);
    CHECK(client != NULL);
    return client;
}

static void check_request(fake_transport *f, const char *method,
                          const char *path, const char *query)
{
    CHECK_STR(f->method, method);
    CHECK_STR(f->path, path);
    if (query == NULL) {
        CHECK(!f->has_query);
    } else {
        CHECK(f->has_query);
        CHECK_STR(f->query, query);
    }
}

static void test_client_lifecycle(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    static int dummy_storage;
    aws_ctx *dummy = (aws_ctx *)(void *)&dummy_storage;

    CHECK(s3_client_init(NULL, dummy, "us-east-1") == EINVAL);
    s3_client *client = NULL;
    CHECK(s3_client_init(&client, NULL, "us-east-1") == EINVAL);
    CHECK(s3_client_init(&client, dummy, NULL) == EINVAL);
    CHECK(s3_client_init(&client, dummy, "") == EINVAL);
    s3_client_free(NULL);

    /* Production constructor only wires aws_request(); construction is enough
     * here because a request would need real credentials/network. */
    s3_client *prod = NULL;
    CHECK(s3_client_init(&prod, dummy, "eu-west-1") == 0);
    CHECK(prod != NULL);
    s3_client_free(prod);
}

static void test_sha256_helpers(void)
{
    const char *abc = "abc";
    char hex[S3_SHA256_HEX_LEN] = "";
    CHECK(s3_sha256_hex(abc, 3, hex) == 0);
    CHECK_STR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    CHECK(s3_sha256_verify(abc, 3, hex) == 0);
    CHECK(s3_sha256_verify(abc, 3,
                           "0000000000000000000000000000000000000000000000000000000000000000") ==
          EBADMSG);
    CHECK(s3_sha256_verify(abc, 3, "short") == EINVAL);
    CHECK(s3_sha256_verify(NULL, 3, hex) == EINVAL);
    CHECK(s3_sha256_hex(NULL, 3, hex) == EINVAL);
}

static void test_error_mapping(void)
{
    CHECK(s3_status_to_errno(200, NULL) == 0);
    CHECK(s3_status_to_errno(204, "") == 0);
    CHECK(s3_status_to_errno(404, "NoSuchKey") == ENOENT);
    CHECK(s3_status_to_errno(404, "NoSuchBucket") == ENOENT);
    CHECK(s3_status_to_errno(404, "NoSuchLifecycleConfiguration") == ENOENT);
    CHECK(s3_status_to_errno(403, "AccessDenied") == EACCES);
    CHECK(s3_status_to_errno(403, "SignatureDoesNotMatch") == EACCES);
    CHECK(s3_status_to_errno(409, "BucketAlreadyOwnedByYou") == EEXIST);
    CHECK(s3_status_to_errno(409, "BucketAlreadyExists") == EEXIST);
    CHECK(s3_status_to_errno(400, "InvalidBucketName") == EINVAL);
    CHECK(s3_status_to_errno(400, "MalformedXML") == EINVAL);
    CHECK(s3_status_to_errno(404, NULL) == ENOENT);
    CHECK(s3_status_to_errno(429, NULL) == EAGAIN);
    CHECK(s3_status_to_errno(500, NULL) == EIO);
}

static void test_put_object(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    f.etag = "\"abc123\"";
    s3_client *client = client_for(&f);

    char etag[S3_ETAG_MAX] = "";
    int rc = s3_put_object(client, "bkt", "dir/key name.txt", "hello", 5,
                           "text/plain", etag);
    CHECK(rc == 0);
    CHECK(f.calls == 1);
    check_request(&f, "PUT", "/bkt/dir/key%20name.txt", NULL);
    CHECK(f.unsigned_payload == 1);
    CHECK(f.has_content_type);
    CHECK_STR(f.content_type, "text/plain");
    CHECK(f.body_len == 5);
    CHECK(f.body != NULL && memcmp(f.body, "hello", 5) == 0);
    CHECK_STR(etag, "abc123");

    /* Failure: XML error code maps to a typed errno. */
    fake_reset(&f);
    f.status = 403;
    f.reply_body = "<Error><Code>AccessDenied</Code></Error>";
    rc = s3_put_object(client, "bkt", "k", "x", 1, NULL, etag);
    CHECK(rc == EACCES);

    CHECK(s3_put_object(NULL, "bkt", "k", "x", 1, NULL, etag) == EINVAL);
    CHECK(s3_put_object(client, NULL, "k", "x", 1, NULL, etag) == EINVAL);
    CHECK(s3_put_object(client, "bkt", "", "x", 1, NULL, etag) == EINVAL);
    CHECK(s3_put_object(client, "bkt", "k", NULL, 3, NULL, etag) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_get_object(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    f.reply_body = "payload";
    s3_client *client = client_for(&f);

    char *data = NULL;
    size_t len = 0;
    CHECK(s3_get_object(client, "bkt", "releases/v1/x.tar", &data, &len) == 0);
    check_request(&f, "GET", "/bkt/releases/v1/x.tar", NULL);
    CHECK(f.unsigned_payload == 1);
    CHECK(len == 7);
    CHECK(data != NULL && memcmp(data, "payload", 7) == 0);
    CHECK(data != NULL && data[7] == '\0');
    free(data);

    fake_reset(&f);
    f.status = 404;
    f.reply_body = "<Error><Code>NoSuchKey</Code></Error>";
    data = (char *)0x1;
    len = 99;
    CHECK(s3_get_object(client, "bkt", "missing", &data, &len) == ENOENT);
    CHECK(data == (char *)0x1);
    CHECK(len == 99);

    fake_reset(&f);
    f.transport_rc = EIO;
    CHECK(s3_get_object(client, "bkt", "k", &data, &len) == EIO);

    CHECK(s3_get_object(NULL, "bkt", "k", &data, &len) == EINVAL);
    CHECK(s3_get_object(client, "bkt", "", &data, &len) == EINVAL);
    CHECK(s3_get_object(client, "bkt", "k", NULL, &len) == EINVAL);
    CHECK(s3_get_object(client, "bkt", "k", &data, NULL) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_head_object(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    f.content_length = "42";
    f.etag = "deadbeef";
    s3_client *client = client_for(&f);

    unsigned long long size = 0;
    char etag[S3_ETAG_MAX] = "";
    CHECK(s3_head_object(client, "bkt", "releases/m", &size, etag) == 0);
    check_request(&f, "HEAD", "/bkt/releases/m", NULL);
    CHECK(f.unsigned_payload == 1);
    CHECK(size == 42);
    CHECK_STR(etag, "deadbeef");

    fake_reset(&f);
    f.status = 404;
    CHECK(s3_head_object(client, "bkt", "missing", &size, etag) == ENOENT);

    CHECK(s3_head_object(NULL, "bkt", "k", &size, etag) == EINVAL);
    CHECK(s3_head_object(client, "bkt", "", &size, etag) == EINVAL);
    CHECK(s3_head_object(client, "bkt", "k", NULL, etag) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_delete_object(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 204;
    s3_client *client = client_for(&f);

    CHECK(s3_delete_object(client, "bkt", "releases/old") == 0);
    check_request(&f, "DELETE", "/bkt/releases/old", NULL);

    fake_reset(&f);
    f.status = 403;
    f.reply_body = "<Error><Code>AccessDenied</Code></Error>";
    CHECK(s3_delete_object(client, "bkt", "k") == EACCES);

    CHECK(s3_delete_object(NULL, "bkt", "k") == EINVAL);
    CHECK(s3_delete_object(client, "bkt", "") == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_get_object_sha256(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    f.reply_body = "abc";
    s3_client *client = client_for(&f);

    const char *digest =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    char *data = NULL;
    size_t len = 0;
    CHECK(s3_get_object_sha256(client, "bkt", "k", digest, &data, &len) == 0);
    CHECK(len == 3);
    CHECK(data != NULL && memcmp(data, "abc", 3) == 0);
    free(data);

    data = (char *)0x1;
    len = 99;
    CHECK(s3_get_object_sha256(client, "bkt", "k",
                               "1111111111111111111111111111111111111111111111111111111111111111",
                               &data, &len) == EBADMSG);
    CHECK(data == (char *)0x1);
    CHECK(len == 99);

    CHECK(s3_get_object_sha256(client, "bkt", "k", NULL, &data, &len) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_list_objects(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    f.reply_body =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Name>bkt</Name><Prefix>releases/</Prefix><KeyCount>2</KeyCount>"
        "<IsTruncated>true</IsTruncated>"
        "<NextContinuationToken>tok+/=</NextContinuationToken>"
        "<Contents><Key>releases/a&amp;b.txt</Key>"
        "<LastModified>2026-01-02T03:04:05.000Z</LastModified>"
        "<ETag>&quot;aaa&quot;</ETag><Size>10</Size></Contents>"
        "<Contents><Key>releases/c</Key>"
        "<LastModified>2026-01-03T00:00:00.000Z</LastModified>"
        "<ETag>\"bbb\"</ETag><Size>20</Size></Contents>"
        "</ListBucketResult>";
    s3_client *client = client_for(&f);

    s3_object_list list = {0};
    CHECK(s3_list_objects_v2(client, "bkt", "releases/", &list) == 0);
    check_request(&f, "GET", "/bkt", "list-type=2&prefix=releases%2F");
    CHECK(list.count == 2);
    CHECK(list.truncated == 1);
    CHECK_STR(list.next_token, "tok+/=");
    if (list.count == 2) {
        CHECK_STR(list.items[0].key, "releases/a&b.txt");
        CHECK_STR(list.items[0].etag, "aaa");
        CHECK(list.items[0].size == 10);
        CHECK_STR(list.items[0].last_modified, "2026-01-02T03:04:05.000Z");
        CHECK_STR(list.items[1].key, "releases/c");
        CHECK_STR(list.items[1].etag, "bbb");
        CHECK(list.items[1].size == 20);
    }
    s3_object_list_free(&list);
    CHECK(list.items == NULL && list.count == 0 && list.next_token == NULL);

    fake_reset(&f);
    f.status = 200;
    f.reply_body = "<ListBucketResult><IsTruncated>false</IsTruncated>"
                   "</ListBucketResult>";
    CHECK(s3_list_objects_v2(client, "bkt", NULL, &list) == 0);
    check_request(&f, "GET", "/bkt", "list-type=2");
    CHECK(list.count == 0);
    CHECK(list.truncated == 0);
    s3_object_list_free(&list);

    fake_reset(&f);
    f.status = 404;
    f.reply_body = "<Error><Code>NoSuchBucket</Code></Error>";
    CHECK(s3_list_objects_v2(client, "bkt", "p/", &list) == ENOENT);
    CHECK(list.items == NULL && list.count == 0);

    CHECK(s3_list_objects_v2(NULL, "bkt", "p/", &list) == EINVAL);
    CHECK(s3_list_objects_v2(client, NULL, "p/", &list) == EINVAL);
    CHECK(s3_list_objects_v2(client, "bkt", "p/", NULL) == EINVAL);

    s3_object_list_free(NULL);
    s3_client_free(client);
    fake_reset(&f);
}

static void test_create_bucket(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    s3_client *client = client_for(&f);

    CHECK(s3_create_bucket(client, "bkt") == 0);
    check_request(&f, "PUT", "/bkt", NULL);
    CHECK(f.unsigned_payload == 1);
    CHECK(f.body_len == 0);

    fake_reset(&f);
    f.status = 409;
    f.reply_body = "<Error><Code>BucketAlreadyOwnedByYou</Code></Error>";
    CHECK(s3_create_bucket(client, "bkt") == EEXIST);
    s3_client_free(client);

    /* Non-us-east-1 sends the LocationConstraint document. */
    fake_reset(&f);
    f.status = 200;
    s3_client *eu = NULL;
    CHECK(s3_client_init_with_transport(&eu, "eu-west-1", fake_send, &f) == 0);
    CHECK(s3_create_bucket(eu, "bkt") == 0);
    check_request(&f, "PUT", "/bkt", NULL);
    CHECK(f.body != NULL);
    if (f.body != NULL) {
        CHECK(strstr(f.body, "<LocationConstraint>eu-west-1</LocationConstraint>") !=
              NULL);
        CHECK(strstr(f.body, "CreateBucketConfiguration") != NULL);
    }
    s3_client_free(eu);

    fake_reset(&f);
    s3_client *c2 = client_for(&f);
    CHECK(s3_create_bucket(NULL, "bkt") == EINVAL);
    CHECK(s3_create_bucket(c2, NULL) == EINVAL);
    CHECK(s3_create_bucket(c2, "bad/bucket") == EINVAL);
    s3_client_free(c2);
    fake_reset(&f);
}

static void test_bucket_ops(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 204;
    s3_client *client = client_for(&f);

    CHECK(s3_delete_bucket(client, "bkt") == 0);
    check_request(&f, "DELETE", "/bkt", NULL);

    fake_reset(&f);
    f.status = 404;
    CHECK(s3_delete_bucket(client, "bkt") == ENOENT);
    CHECK(s3_delete_bucket(NULL, "bkt") == EINVAL);

    fake_reset(&f);
    f.status = 200;
    CHECK(s3_head_bucket(client, "bkt") == 0);
    check_request(&f, "HEAD", "/bkt", NULL);

    fake_reset(&f);
    f.status = 404;
    CHECK(s3_head_bucket(client, "bkt") == ENOENT);
    CHECK(s3_head_bucket(client, NULL) == EINVAL);

    fake_reset(&f);
    f.status = 200;
    f.reply_body =
        "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "eu-west-1</LocationConstraint>";
    char region[64] = "";
    CHECK(s3_get_bucket_location(client, "bkt", region, sizeof(region)) == 0);
    check_request(&f, "GET", "/bkt", "location=");
    CHECK_STR(region, "eu-west-1");

    fake_reset(&f);
    f.status = 200;
    f.reply_body =
        "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
    CHECK(s3_get_bucket_location(client, "bkt", region, sizeof(region)) == 0);
    CHECK_STR(region, "us-east-1");

    fake_reset(&f);
    f.status = 404;
    CHECK(s3_get_bucket_location(client, "bkt", region, sizeof(region)) ==
          ENOENT);
    CHECK(s3_get_bucket_location(client, "bkt", NULL, sizeof(region)) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_versioning(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    s3_client *client = client_for(&f);

    CHECK(s3_set_versioning(client, "bkt", 1) == 0);
    check_request(&f, "PUT", "/bkt", "versioning=");
    CHECK(f.body != NULL && strstr(f.body, "<Status>Enabled</Status>") != NULL);

    fake_reset(&f);
    f.status = 200;
    CHECK(s3_set_versioning(client, "bkt", 0) == 0);
    CHECK(f.body != NULL && strstr(f.body, "<Status>Suspended</Status>") != NULL);

    fake_reset(&f);
    f.status = 200;
    f.reply_body =
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Status>Enabled</Status></VersioningConfiguration>";
    int enabled = -1;
    CHECK(s3_get_versioning(client, "bkt", &enabled) == 0);
    check_request(&f, "GET", "/bkt", "versioning=");
    CHECK(enabled == 1);

    fake_reset(&f);
    f.status = 200;
    f.reply_body = "<VersioningConfiguration><Status>Suspended</Status>"
                   "</VersioningConfiguration>";
    CHECK(s3_get_versioning(client, "bkt", &enabled) == 0);
    CHECK(enabled == 0);

    fake_reset(&f);
    f.status = 404;
    f.reply_body = "<Error><Code>NoSuchBucket</Code></Error>";
    CHECK(s3_get_versioning(client, "bkt", &enabled) == ENOENT);
    CHECK(s3_get_versioning(client, "bkt", NULL) == EINVAL);
    CHECK(s3_set_versioning(NULL, "bkt", 1) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_public_access_block(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    s3_client *client = client_for(&f);

    s3_public_access_block block = {1, 1, 1, 1};
    CHECK(s3_set_public_access_block(client, "bkt", &block) == 0);
    check_request(&f, "PUT", "/bkt", "publicAccessBlock=");
    CHECK(f.body != NULL);
    if (f.body != NULL) {
        CHECK(strstr(f.body, "<BlockPublicAcls>true</BlockPublicAcls>") != NULL);
        CHECK(strstr(f.body, "<IgnorePublicAcls>true</IgnorePublicAcls>") != NULL);
        CHECK(strstr(f.body, "<BlockPublicPolicy>true</BlockPublicPolicy>") != NULL);
        CHECK(strstr(f.body, "<RestrictPublicBuckets>true</RestrictPublicBuckets>") !=
              NULL);
    }

    fake_reset(&f);
    f.status = 200;
    f.reply_body =
        "<PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<BlockPublicAcls>true</BlockPublicAcls>"
        "<IgnorePublicAcls>false</IgnorePublicAcls>"
        "<BlockPublicPolicy>true</BlockPublicPolicy>"
        "<RestrictPublicBuckets>false</RestrictPublicBuckets>"
        "</PublicAccessBlockConfiguration>";
    s3_public_access_block out = {0, 0, 0, 0};
    CHECK(s3_get_public_access_block(client, "bkt", &out) == 0);
    check_request(&f, "GET", "/bkt", "publicAccessBlock=");
    CHECK(out.block_public_acls == 1);
    CHECK(out.ignore_public_acls == 0);
    CHECK(out.block_public_policy == 1);
    CHECK(out.restrict_public_buckets == 0);

    fake_reset(&f);
    f.status = 404;
    f.reply_body = "<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>";
    CHECK(s3_get_public_access_block(client, "bkt", &out) == ENOENT);
    CHECK(s3_set_public_access_block(client, "bkt", NULL) == EINVAL);
    CHECK(s3_get_public_access_block(client, "bkt", NULL) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_encryption(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    s3_client *client = client_for(&f);

    CHECK(s3_set_encryption(client, "bkt", "AES256", NULL) == 0);
    check_request(&f, "PUT", "/bkt", "encryption=");
    CHECK(f.body != NULL &&
          strstr(f.body, "<SSEAlgorithm>AES256</SSEAlgorithm>") != NULL);
    CHECK(f.body == NULL || strstr(f.body, "KMSMasterKeyID") == NULL);

    fake_reset(&f);
    f.status = 200;
    CHECK(s3_set_encryption(client, "bkt", "aws:kms", "alias/k") == 0);
    CHECK(f.body != NULL &&
          strstr(f.body, "<SSEAlgorithm>aws:kms</SSEAlgorithm>") != NULL);
    CHECK(f.body != NULL &&
          strstr(f.body, "<KMSMasterKeyID>alias/k</KMSMasterKeyID>") != NULL);

    fake_reset(&f);
    f.status = 200;
    f.reply_body =
        "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Rule><ApplyServerSideEncryptionByDefault>"
        "<SSEAlgorithm>AES256</SSEAlgorithm>"
        "</ApplyServerSideEncryptionByDefault></Rule>"
        "</ServerSideEncryptionConfiguration>";
    char algorithm[32] = "";
    CHECK(s3_get_encryption(client, "bkt", algorithm, sizeof(algorithm)) == 0);
    check_request(&f, "GET", "/bkt", "encryption=");
    CHECK_STR(algorithm, "AES256");

    fake_reset(&f);
    f.status = 404;
    f.reply_body =
        "<Error><Code>ServerSideEncryptionConfigurationNotFoundError</Code></Error>";
    CHECK(s3_get_encryption(client, "bkt", algorithm, sizeof(algorithm)) ==
          ENOENT);
    CHECK(s3_set_encryption(client, "bkt", NULL, NULL) == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

static void test_lifecycle(void)
{
    fake_transport f = {0};
    fake_reset(&f);
    f.status = 200;
    s3_client *client = client_for(&f);

    const char *xml =
        "<LifecycleConfiguration><Rule><ID>mpu-abort</ID>"
        "<AbortIncompleteMultipartUpload><DaysAfterInitiation>7"
        "</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>"
        "</LifecycleConfiguration>";
    CHECK(s3_put_lifecycle(client, "bkt", xml) == 0);
    check_request(&f, "PUT", "/bkt", "lifecycle=");
    CHECK(f.body != NULL && strcmp(f.body, xml) == 0);

    fake_reset(&f);
    f.status = 200;
    f.reply_body = xml;
    char *got = NULL;
    CHECK(s3_get_lifecycle(client, "bkt", &got) == 0);
    check_request(&f, "GET", "/bkt", "lifecycle=");
    CHECK(got != NULL && strcmp(got, xml) == 0);
    free(got);

    fake_reset(&f);
    f.status = 204;
    CHECK(s3_delete_lifecycle(client, "bkt") == 0);
    check_request(&f, "DELETE", "/bkt", "lifecycle=");

    fake_reset(&f);
    f.status = 404;
    f.reply_body = "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>";
    CHECK(s3_get_lifecycle(client, "bkt", &got) == ENOENT);
    CHECK(s3_put_lifecycle(client, "bkt", NULL) == EINVAL);
    CHECK(s3_get_lifecycle(client, "bkt", NULL) == EINVAL);
    CHECK(s3_delete_lifecycle(NULL, "bkt") == EINVAL);

    s3_client_free(client);
    fake_reset(&f);
}

int main(void)
{
    test_client_lifecycle();
    test_sha256_helpers();
    test_error_mapping();
    test_put_object();
    test_get_object();
    test_head_object();
    test_delete_object();
    test_get_object_sha256();
    test_list_objects();
    test_create_bucket();
    test_bucket_ops();
    test_versioning();
    test_public_access_block();
    test_encryption();
    test_lifecycle();

    if (failures != 0) {
        fprintf(stderr, "s3_test: %d/%d checks failed\n", failures, checks);
        return 1;
    }
    printf("s3_test: %d checks passed\n", checks);
    return 0;
}
