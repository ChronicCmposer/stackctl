/*
 * cli_output_test.c — output, table, JSON, redaction, confirmation, usage,
 * error-rendering and exit-code classification tests.
 */

#include "cli.h"
#include "yyjson.h"

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
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

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

/* ------------------------------------------------------------------------- */
/* Stream capture helpers                                                    */
/* ------------------------------------------------------------------------- */

typedef struct capture {
    FILE *saved;
    FILE *temporary;
    int fd;
    int target;
} capture;

static int capture_begin(capture *cap, int target) {
    fflush(NULL);
    cap->target = target;
    cap->temporary = tmpfile();
    if (cap->temporary == NULL) {
        return -1;
    }
    cap->saved = target == STDOUT_FILENO ? stdout : stderr;
    cap->fd = dup(target);
    if (cap->fd < 0) {
        fclose(cap->temporary);
        return -1;
    }
    if (dup2(fileno(cap->temporary), target) < 0) {
        close(cap->fd);
        fclose(cap->temporary);
        return -1;
    }
    return 0;
}

static char *capture_end(capture *cap) {
    long size;
    char *text;

    fflush(NULL);
    dup2(cap->fd, cap->target);
    close(cap->fd);
    if (fseek(cap->temporary, 0, SEEK_END) != 0) {
        fclose(cap->temporary);
        return NULL;
    }
    size = ftell(cap->temporary);
    if (size < 0 || fseek(cap->temporary, 0, SEEK_SET) != 0) {
        fclose(cap->temporary);
        return NULL;
    }
    text = calloc((size_t)size + 1, 1);
    if (text != NULL && size > 0) {
        if (fread(text, 1, (size_t)size, cap->temporary) != (size_t)size) {
            free(text);
            text = NULL;
        }
    }
    fclose(cap->temporary);
    return text;
}

static char *read_stream(FILE *stream) {
    long size;
    char *text;

    fflush(stream);
    if (fseek(stream, 0, SEEK_END) != 0) {
        return NULL;
    }
    size = ftell(stream);
    if (size < 0 || fseek(stream, 0, SEEK_SET) != 0) {
        return NULL;
    }
    text = calloc((size_t)size + 1, 1);
    if (text != NULL && size > 0) {
        if (fread(text, 1, (size_t)size, stream) != (size_t)size) {
            free(text);
            text = NULL;
        }
    }
    return text;
}

/* ------------------------------------------------------------------------- */
/* Table                                                                     */
/* ------------------------------------------------------------------------- */

static void test_table(void) {
    const char *headers[] = {"NAME", "STATE"};
    const char *cells[] = {"web", "running", "db", "stopped"};
    cli_table table = {headers, 2, cells, 2};
    FILE *out = tmpfile();
    char *text;

    CHECK(out != NULL, "tmpfile");
    if (out == NULL) {
        return;
    }
    CHECK(cli_table_write(out, &table) == 0, "table writes");
    text = read_stream(out);
    fclose(out);
    CHECK(text != NULL, "table text");
    if (text != NULL) {
        CHECK(strcmp(text, "NAME  STATE\n"
                           "web   running\n"
                           "db    stopped\n") == 0,
              "aligned table output");
        free(text);
    }

    CHECK(cli_table_write(NULL, &table) == EINVAL, "NULL stream is EINVAL");
    CHECK(cli_table_write(tmpfile(), NULL) == EINVAL, "NULL table is EINVAL");

    cli_table empty = {headers, 0, cells, 2};
    CHECK(cli_table_write(tmpfile(), &empty) == EINVAL, "zero columns");
    cli_table no_headers = {NULL, 2, cells, 2};
    CHECK(cli_table_write(tmpfile(), &no_headers) == EINVAL, "NULL headers");
    cli_table no_cells = {headers, 2, NULL, 2};
    CHECK(cli_table_write(tmpfile(), &no_cells) == EINVAL, "NULL cells");
}

/* ------------------------------------------------------------------------- */
/* JSON                                                                      */
/* ------------------------------------------------------------------------- */

static void test_json(void) {
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    FILE *out;
    char *text;

    CHECK(doc != NULL && root != NULL, "json doc");
    if (doc == NULL || root == NULL) {
        yyjson_mut_doc_free(doc);
        return;
    }
    yyjson_mut_doc_set_root(doc, root);
    CHECK(yyjson_mut_obj_add_str(doc, root, "status", "ok"), "json str");
    CHECK(yyjson_mut_obj_add_int(doc, root, "count", 3), "json int");

    out = tmpfile();
    CHECK(out != NULL, "json tmpfile");
    CHECK(cli_json_write(out, doc) == 0, "json writes");
    text = read_stream(out);
    fclose(out);
    CHECK(text != NULL, "json text");
    if (text != NULL) {
        CHECK(strstr(text, "\"status\": \"ok\"") != NULL, "json content");
        CHECK(strstr(text, "\"count\": 3") != NULL, "json int content");
        size_t len = strlen(text);
        CHECK(len > 0 && text[len - 1] == '\n', "json trailing newline");
        free(text);
    }
    CHECK(cli_json_write(tmpfile(), NULL) == EINVAL, "NULL doc is EINVAL");
    CHECK(cli_json_write(NULL, doc) == EINVAL, "NULL stream is EINVAL");
    yyjson_mut_doc_free(doc);

    capture cap;
    CHECK(capture_begin(&cap, STDOUT_FILENO) == 0, "capture stdout");
    doc = yyjson_mut_doc_new(NULL);
    root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    yyjson_mut_obj_add_bool(doc, root, "ok", true);
    CHECK(cli_json_emit(doc) == 0, "json emit");
    yyjson_mut_doc_free(doc);
    text = capture_end(&cap);
    CHECK(text != NULL && strstr(text, "\"ok\": true") != NULL,
          "json emit goes to stdout");
    free(text);
}

/* ------------------------------------------------------------------------- */
/* Redaction                                                                 */
/* ------------------------------------------------------------------------- */

static void test_redaction(void) {
    char out[256];
    {
        const char *argv[] = {"deploy", "--password", "hunter2", "--region",
                              "us-east-1"};
        CHECK(cli_redact_args(argv, ARRAY_LEN(argv), out, sizeof(out)) == 0,
              "redact long password");
        CHECK(strcmp(out, "deploy --password=<redacted> --region us-east-1") ==
                  0,
              "password operand hidden");
    }
    {
        const char *argv[] = {"x", "--api-token=abc", "keep"};
        CHECK(cli_redact_args(argv, ARRAY_LEN(argv), out, sizeof(out)) == 0,
              "redact = form");
        CHECK(strcmp(out, "x --api-token=<redacted> keep") == 0,
              "= form hidden");
    }
    {
        const char *argv[] = {"APP_SECRET_KEY=shh", "AWS_ACCESS_KEY_ID",
                              "AKIAEXAMPLE"};
        CHECK(cli_redact_args(argv, ARRAY_LEN(argv), out, sizeof(out)) == 0,
              "redact env form");
        CHECK(strcmp(out,
                     "APP_SECRET_KEY=<redacted> AWS_ACCESS_KEY_ID "
                     "AKIAEXAMPLE") == 0,
              "env secret hidden, access key id kept");
    }
    {
        const char *argv[] = {"--password"};
        CHECK(cli_redact_args(argv, ARRAY_LEN(argv), out, sizeof(out)) == 0,
              "redact dangling password flag");
        CHECK(strcmp(out, "--password=<redacted>") == 0, "dangling hidden");
    }
    {
        const char *argv[] = {"--project=/srv/cfg", "deploy"};
        CHECK(cli_redact_args(argv, ARRAY_LEN(argv), out, sizeof(out)) == 0,
              "redact non-secret");
        CHECK(strcmp(out, "--project=/srv/cfg deploy") == 0,
              "non-secret untouched");
    }
    {
        const char *argv[] = {"--password", "hunter2"};
        char tiny[8];
        CHECK(cli_redact_args(argv, ARRAY_LEN(argv), tiny, sizeof(tiny)) ==
                  ERANGE,
              "small buffer is ERANGE");
        CHECK(tiny[sizeof(tiny) - 1] == '\0', "small buffer terminated");
    }
    {
        CHECK(cli_redact_args(NULL, 1, out, sizeof(out)) == EINVAL,
              "NULL argv is EINVAL");
        CHECK(cli_redact_args(NULL, 0, out, sizeof(out)) == 0, "empty args");
        CHECK(strcmp(out, "") == 0, "empty redaction");
        CHECK(cli_redact_args(NULL, 0, NULL, 0) == EINVAL, "NULL out");
    }
}

/* ------------------------------------------------------------------------- */
/* Confirmation                                                              */
/* ------------------------------------------------------------------------- */

static FILE *input_stream(const char *text) {
    FILE *file = tmpfile();

    if (file == NULL) {
        return NULL;
    }
    if (text != NULL) {
        fputs(text, file);
    }
    fflush(file);
    rewind(file);
    return file;
}

static void test_confirm(void) {
    char prompt[128];

    {
        FILE *in = input_stream("y\n");
        FILE *out = tmpfile();
        CHECK(cli_confirm_stream(in, out, 1, 0, "apply? [y/N] ") ==
                  CLI_CONFIRM_YES,
              "y confirms");
        memset(prompt, 0, sizeof(prompt));
        rewind(out);
        CHECK(fread(prompt, 1, sizeof(prompt) - 1, out) > 0, "prompt written");
        CHECK(strcmp(prompt, "apply? [y/N] ") == 0, "prompt text");
        fclose(in);
        fclose(out);
    }
    {
        FILE *in = input_stream("YES\n");
        FILE *out = tmpfile();
        CHECK(cli_confirm_stream(in, out, 1, 0, "p ") == CLI_CONFIRM_YES,
              "YES confirms");
        fclose(in);
        fclose(out);
    }
    {
        FILE *in = input_stream("\n");
        FILE *out = tmpfile();
        CHECK(cli_confirm_stream(in, out, 1, 0, "p ") == CLI_CONFIRM_NO,
              "empty declines");
        fclose(in);
        fclose(out);
    }
    {
        FILE *in = input_stream("n\n");
        FILE *out = tmpfile();
        CHECK(cli_confirm_stream(in, out, 1, 0, "p ") == CLI_CONFIRM_NO,
              "n declines");
        fclose(in);
        fclose(out);
    }
    {
        FILE *in = input_stream("");
        FILE *out = tmpfile();
        CHECK(cli_confirm_stream(in, out, 1, 0, "p ") == CLI_CONFIRM_EOF,
              "EOF reported");
        fclose(in);
        fclose(out);
    }
    {
        FILE *in = input_stream("y\n");
        FILE *out = tmpfile();
        CHECK(cli_confirm_stream(in, out, 0, 0, "p ") ==
                  CLI_CONFIRM_NONINTERACTIVE,
              "non-interactive without --yes");
        CHECK(cli_confirm_stream(in, out, 0, 1, "p ") == CLI_CONFIRM_YES,
              "--yes short-circuits");
        CHECK(cli_confirm_stream(in, out, 1, 1, "p ") == CLI_CONFIRM_YES,
              "--yes works interactively too");
        fclose(in);
        fclose(out);
    }
    {
        FILE *file = tmpfile();
        CHECK(cli_is_tty(file) == 0, "tmpfile is not a tty");
        fclose(file);
        CHECK(cli_is_tty(NULL) == 0, "NULL stream is not a tty");
    }
}

/* ------------------------------------------------------------------------- */
/* Usage / errors / exit mapping                                             */
/* ------------------------------------------------------------------------- */

static void test_usage(void) {
    FILE *out = tmpfile();
    char *text;

    CHECK(out != NULL, "usage tmpfile");
    if (out == NULL) {
        return;
    }
    cli_print_global_usage(out, "stackctl");
    text = read_stream(out);
    fclose(out);
    CHECK(text != NULL, "usage text");
    if (text != NULL) {
        CHECK(strstr(text, "Usage: stackctl") != NULL, "usage synopsis");
        CHECK(strstr(text, "--project") != NULL, "usage project flag");
        CHECK(strstr(text, "--lock-timeout") != NULL, "usage timeout flag");
        free(text);
    }

    static const cli_command command = {
        "provision", "Create/update the operator stack", "provision [--rotate]",
        NULL, 1, 1,
    };
    static const cli_option_spec options[] = {
        {"rotate", 'r', 0, 0, NULL, "rotate the operator key"},
    };
    out = tmpfile();
    CHECK(out != NULL, "command usage tmpfile");
    if (out == NULL) {
        return;
    }
    cli_print_command_usage(out, "stackctl", &command, options,
                            ARRAY_LEN(options));
    text = read_stream(out);
    fclose(out);
    CHECK(text != NULL, "command usage text");
    if (text != NULL) {
        CHECK(strstr(text, "provision [--rotate]") != NULL, "command usage");
        CHECK(strstr(text, "operator stack") != NULL, "command summary");
        CHECK(strstr(text, "--rotate") != NULL, "option rendered");
        free(text);
    }
}

static void test_fail_and_exit_mapping(void) {
    capture cap;
    char *text;

    CHECK(cli_rc_to_exit(0) == CLI_EXIT_OK, "rc 0");
    CHECK(cli_rc_to_exit(EINVAL) == CLI_EXIT_USAGE, "EINVAL -> usage");
    CHECK(cli_rc_to_exit(ETIMEDOUT) == CLI_EXIT_USAGE, "ETIMEDOUT -> usage");
    CHECK(cli_rc_to_exit(EIO) == CLI_EXIT_AWS, "EIO -> AWS");

    CHECK(capture_begin(&cap, STDERR_FILENO) == 0, "capture stderr");
    CHECK(cli_fail(NULL, CLI_EXIT_VERIFY, "bad %s", "state") ==
              CLI_EXIT_VERIFY,
          "fail returns code");
    text = capture_end(&cap);
    CHECK(text != NULL && strcmp(text, "stackctl: bad state\n") == 0,
          "fail stderr text");
    free(text);

    CHECK(capture_begin(&cap, STDERR_FILENO) == 0, "capture warn");
    cli_warn(NULL, "careful %d", 7);
    text = capture_end(&cap);
    CHECK(text != NULL && strcmp(text, "stackctl: warning: careful 7\n") == 0,
          "warn stderr text");
    free(text);

    CHECK(capture_begin(&cap, STDOUT_FILENO) == 0, "capture stdout");
    cli_out("hello %s\n", "world");
    text = capture_end(&cap);
    CHECK(text != NULL && strcmp(text, "hello world\n") == 0, "out stdout");
    free(text);

    CHECK(capture_begin(&cap, STDERR_FILENO) == 0, "capture err");
    cli_err("err %d\n", 3);
    text = capture_end(&cap);
    CHECK(text != NULL && strcmp(text, "err 3\n") == 0, "err stderr");
    free(text);
}

int main(void) {
    test_table();
    test_json();
    test_redaction();
    test_confirm();
    test_usage();
    test_fail_and_exit_mapping();

    if (failures != 0) {
        fprintf(stderr, "cli_output_test: %d check(s) failed\n", failures);
        return 1;
    }
    printf("cli_output_test: all checks passed\n");
    return 0;
}
