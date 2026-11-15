/*
 * template_check — dependency-free structural validator for the canonical
 * stackctl CloudFormation templates (spec §6.1/§6.2/§6.3).
 *
 * The same implementation is used by the colocated cc_test and is intended to
 * be reused as the fail-closed runtime gate for TEMPLATE_OVERRIDE files.
 *
 * Return values:
 *   0  template satisfies the contracted structure
 *   1  one or more structural violations (diagnostics on stderr)
 *   2  IO or YAML-subset parse error (diagnostics on stderr)
 */

#ifndef STACKCTL_DEPLOY_CHECK_TEMPLATE_CHECK_H_
#define STACKCTL_DEPLOY_CHECK_TEMPLATE_CHECK_H_

#include <stddef.h>

typedef enum {
    TC_MODE_OPERATOR = 0,
    TC_MODE_INFRA = 1
} tc_mode;

int tc_check_string(const char *text, size_t length, tc_mode mode);
/* Same as tc_check_string but labels diagnostics with the source path. */
int tc_check_buffer(const char *path, const char *text, size_t length,
                    tc_mode mode);
int tc_check_file(const char *path, tc_mode mode);

#endif /* STACKCTL_DEPLOY_CHECK_TEMPLATE_CHECK_H_ */
