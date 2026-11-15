#include "template_check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect(int condition, const char *what) {
    g_checks++;
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", what);
        g_failures++;
    }
}

static char *runfile(const char *relative) {
    const char *srcdir = getenv("TEST_SRCDIR");
    const char *workspace = getenv("TEST_WORKSPACE");
    if (srcdir == NULL || workspace == NULL) {
        return NULL;
    }
    size_t size = strlen(srcdir) + strlen(workspace) + strlen(relative) + 3;
    char *path = malloc(size);
    if (path == NULL) {
        return NULL;
    }
    snprintf(path, size, "%s/%s/%s", srcdir, workspace, relative);
    return path;
}

static void expect_file(int want, const char *relative, tc_mode mode) {
    char *path = runfile(relative);
    if (path == NULL) {
        expect(0, "runfile resolution unavailable");
        return;
    }
    int got = tc_check_file(path, mode);
    free(path);
    g_checks++;
    if (got != want) {
        fprintf(stderr, "FAIL: %s: expected %d, got %d\n", relative, want, got);
        g_failures++;
    }
}

static void expect_string(int want, const char *text, tc_mode mode, const char *what) {
    int got = tc_check_string(text, strlen(text), mode);
    g_checks++;
    if (got != want) {
        fprintf(stderr, "FAIL: %s: expected %d, got %d\n", what, want, got);
        g_failures++;
    }
}

int main(void) {
    expect_string(1, "AWSTemplateFormatVersion: \"2010-09-09\"\n", TC_MODE_INFRA,
                  "missing sections rejected");

    expect_file(0, "deploy/stackctl-operator.yaml", TC_MODE_OPERATOR);
    expect_file(0, "deploy/stackctl-infra.yaml", TC_MODE_INFRA);

    /* Each negative fixture is otherwise-valid and violates exactly the one
     * named rule, so a regression in any single check fails its own test. */
    expect_file(1, "deploy/check/testdata/bad_operator_wildcard.yaml", TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_infra_export.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_bucket.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_literal_cidr.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_operator_action_intrinsic.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_resource_intrinsic.yaml",
                TC_MODE_OPERATOR);

    if (g_failures != 0) {
        fprintf(stderr, "%d/%d checks failed\n", g_failures, g_checks);
        return 1;
    }
    printf("template_check_test: %d checks passed\n", g_checks);
    return 0;
}
