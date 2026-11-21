#include "template_check.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* The acceptance fixtures assert on the diagnostic text, not merely the exit
 * code: a fixture must produce the diagnostic naming its violated rule, and a
 * pass fixture must not produce any S3-scope diagnostic at all. Capturing
 * stderr around the call keeps tc_check_file's public contract unchanged. */
static char *drain(FILE *file) {
    if (fseek(file, 0, SEEK_END) != 0) {
        return NULL;
    }
    long size = ftell(file);
    if (size < 0) {
        return NULL;
    }
    rewind(file);
    char *text = malloc((size_t)size + 1);
    if (text == NULL) {
        return NULL;
    }
    size_t got = fread(text, 1, (size_t)size, file);
    text[got] = '\0';
    return text;
}

/* Runs tc_check_file with stderr redirected to a temp file and returns the
 * captured diagnostics (caller frees). *status is set to the checker result,
 * or -1 when the harness itself could not capture. */
static char *check_file_capture(const char *relative, tc_mode mode, int *status) {
    char *path = runfile(relative);
    if (path == NULL) {
        *status = -1;
        return NULL;
    }
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    FILE *capture = tmpfile();
    if (saved < 0 || capture == NULL) {
        if (capture != NULL) {
            fclose(capture);
        }
        if (saved >= 0) {
            close(saved);
        }
        free(path);
        *status = -1;
        return NULL;
    }
    dup2(fileno(capture), STDERR_FILENO);
    int got = tc_check_file(path, mode);
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);
    char *diagnostics = drain(capture);
    fclose(capture);
    free(path);
    *status = got;
    return diagnostics;
}

static void expect_fixture_clean(const char *relative, tc_mode mode,
                                 const char *const *forbidden, size_t forbidden_count) {
    int got = -1;
    char *diagnostics = check_file_capture(relative, mode, &got);
    if (diagnostics == NULL) {
        expect(0, "diagnostic capture unavailable");
        return;
    }
    g_checks++;
    if (got != 0) {
        fprintf(stderr, "FAIL: %s: expected clean exit, got %d\n%s", relative, got,
                diagnostics);
        g_failures++;
    }
    for (size_t i = 0; i < forbidden_count; i++) {
        g_checks++;
        if (strstr(diagnostics, forbidden[i]) != NULL) {
            fprintf(stderr, "FAIL: %s: unexpected diagnostic containing \"%s\"\n",
                    relative, forbidden[i]);
            g_failures++;
        }
    }
    free(diagnostics);
}

/* rule_text must appear in the diagnostics; detail (optional) pins the exact
 * violating value so a baseline failure cannot mask the targeted rule. */
static void expect_fixture_violation(const char *relative, tc_mode mode,
                                     const char *rule_text, const char *detail) {
    int got = -1;
    char *diagnostics = check_file_capture(relative, mode, &got);
    if (diagnostics == NULL) {
        expect(0, "diagnostic capture unavailable");
        return;
    }
    g_checks++;
    if (got != 1) {
        fprintf(stderr, "FAIL: %s: expected violation exit, got %d\n%s", relative, got,
                diagnostics);
        g_failures++;
    }
    g_checks++;
    if (strstr(diagnostics, rule_text) == NULL) {
        fprintf(stderr, "FAIL: %s: missing rule diagnostic \"%s\"\n%s", relative,
                rule_text, diagnostics);
        g_failures++;
    }
    if (detail != NULL) {
        g_checks++;
        if (strstr(diagnostics, detail) == NULL) {
            fprintf(stderr, "FAIL: %s: missing detail \"%s\"\n%s", relative, detail,
                    diagnostics);
            g_failures++;
        }
    }
    free(diagnostics);
}

int main(void) {
    expect_string(1, "AWSTemplateFormatVersion: \"2010-09-09\"\n", TC_MODE_INFRA,
                  "missing sections rejected");

    expect_file(0, "deploy/stackctl-operator.yaml", TC_MODE_OPERATOR);
    expect_file(0, "deploy/stackctl-infra.yaml", TC_MODE_INFRA);

    /* Each negative fixture is otherwise-valid and violates exactly the one
     * named rule, so a regression in any single check fails its own test. */
    expect_file(1, "deploy/check/testdata/bad_operator_wildcard.yaml", TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_runinstances_createaction.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_createaction_prefixed.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_infra_ami_asymmetry.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_ami_asymmetry_unref.yaml",
                TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_export.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_bucket.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_literal_cidr.yaml", TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_operator_action_intrinsic.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_resource_intrinsic.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_missing_user_policy.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_missing_imagebuilder_perms.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_missing_bucket_lifecycle.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_missing_bucket_public_access_block.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_operator_ib_execution_trust.yaml",
                TC_MODE_OPERATOR);
    expect_file(1, "deploy/check/testdata/bad_infra_baked_distribution.yaml",
                TC_MODE_INFRA);
    expect_file(1, "deploy/check/testdata/bad_infra_baked_parent.yaml",
                TC_MODE_INFRA);

    /* v0.2.0 checker acceptance fixtures (CONTRACT checker rules 1-5). */
    static const char *const scope_diagnostics[] = {
        "operator S3 object resource is not an own-project !Sub literal",
        "operator ListBucket resource must be the own project artifact bucket ARN",
        "ArtifactReaderPolicy may grant only s3:GetObject and s3:ListBucket",
        "ArtifactReaderPolicy GetObject resource must be an own-project !Sub literal",
        "ArtifactReaderPolicy ListBucket resource must be the own project artifact bucket ARN",
    };
    const size_t scope_diagnostic_count =
        sizeof(scope_diagnostics) / sizeof(scope_diagnostics[0]);

    /* Rule 1: bucket-wide !Sub object grant on the own bucket is clean. */
    expect_fixture_clean("deploy/check/testdata/operator_bucketwide_own.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);
    /* Rule 2: an unconditioned ListBucket on the own bucket is clean. */
    expect_fixture_clean("deploy/check/testdata/list_unconditioned_own.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);
    /* Rule 4: CI reader with GetObject+ListBucket only is clean. */
    expect_fixture_clean("deploy/check/testdata/ci_read_bucketwide.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);

    /* Rule 1: wildcard bucket in an object resource. */
    expect_fixture_violation("deploy/check/testdata/wildcard_bucket_objects.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0], "arn:aws:s3:::*/x/*");
    /* Rule 2: ListBucket names a bucket wildcard. */
    expect_fixture_violation("deploy/check/testdata/wildcard_list.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[1], "arn:aws:s3:::*");
    /* Rule 1: another project's bucket. */
    expect_fixture_violation("deploy/check/testdata/other_project_bucket.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0],
                             "otherproject-artifacts");
    /* Rule 3: the Users-attached policy is collected and flagged specifically. */
    expect_fixture_violation("deploy/check/testdata/users_attached_other_bucket.yaml",
                             TC_MODE_OPERATOR, "(attached via Users)",
                             "otherproject-artifacts");
    /* Rule 1: opaque !GetAtt object resource. */
    expect_fixture_violation("deploy/check/testdata/opaque_getatt_resource.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0],
                             "!GetAtt ArtifactBucket.Arn");
    /* Rule 4: CI reader grants PutObject. */
    expect_fixture_violation("deploy/check/testdata/ci_putobject.yaml", TC_MODE_OPERATOR,
                             scope_diagnostics[2], "s3:PutObject");
    /* Rule 4: CI reader reads another project's bucket. */
    expect_fixture_violation("deploy/check/testdata/ci_other_bucket.yaml", TC_MODE_OPERATOR,
                             scope_diagnostics[3], "otherproject-artifacts");

    /* D1: long-form intrinsic Action/Resource nodes must fail closed rather
     * than being skipped by the scalar-only walk. */
    static const char *const unsupported_action =
        "operator S3 policy Action uses an unsupported intrinsic shape";
    expect_fixture_violation("deploy/check/testdata/intrinsic_action_ref.yaml",
                             TC_MODE_OPERATOR, unsupported_action, "Ref");
    expect_fixture_violation("deploy/check/testdata/intrinsic_action_if.yaml",
                             TC_MODE_OPERATOR, unsupported_action, "Ref");
    expect_fixture_violation("deploy/check/testdata/intrinsic_resource_ref.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0], "Ref");
    expect_fixture_violation("deploy/check/testdata/intrinsic_resource_sub.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0], "/releases/*");
    expect_fixture_violation("deploy/check/testdata/intrinsic_resource_join.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0], "Fn::Join");
    expect_fixture_violation("deploy/check/testdata/intrinsic_resource_if.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0], "Ref");

    /* D4: a bare literal that merely matches the own-bucket text is not the
     * contract-required !Sub intrinsic form. */
    expect_fixture_violation("deploy/check/testdata/bare_literal_object_resource.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0],
                             "arn:aws:s3:::${ProjectName}-artifacts-${AWS::AccountId}-*/*");

    /* D2: an AWS::IAM::Policy attached via Users to the operator user is
     * collected under the same scope rules. */
    expect_fixture_violation("deploy/check/testdata/attached_policy_other_bucket.yaml",
                             TC_MODE_OPERATOR, "(attached via Users)",
                             "otherproject-artifacts");

    /* D3: attached policies past OPERATOR_MAX_POLICIES are a violation. */
    expect_fixture_violation("deploy/check/testdata/operator_policy_overflow.yaml",
                             TC_MODE_OPERATOR,
                             "operator policy union exceeds the supported maximum of 8",
                             NULL);

    /* D5: the Fn::Sub sequence form carries a substitution map that can rebind
     * ${ProjectName}/${AWS::AccountId}; it must fail closed on the S3-scope
     * rules rather than trusting the template string and ignoring the map. */
    expect_fixture_violation("deploy/check/testdata/sub_map_resource.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[0], "Fn::Sub");
    expect_fixture_violation("deploy/check/testdata/sub_map_action.yaml",
                             TC_MODE_OPERATOR, unsupported_action, "Fn::Sub");

    /* D6: a bucket-handler statement on another project's bucket must still be
     * held to rule 2; the exemption is limited to the own and certs buckets. */
    expect_fixture_violation("deploy/check/testdata/bucket_handler_other_bucket.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[1],
                             "otherproject-artifacts");

    /* D7: rule 4 identifies the CI reader by its attachment to the CI identity,
     * so a non-canonical logical id is still inspected. */
    expect_fixture_violation("deploy/check/testdata/ci_reader_noncanonical_id.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    /* D8 (a): a non-canonical reader attached from the IDENTITY side through
     * CiUser.ManagedPolicyArns must be resolved and held to rule 4. */
    expect_fixture_violation("deploy/check/testdata/ci_reader_via_identity_arn.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    /* D8 (b): a non-canonical reader attached by the identity's NAME
     * (Users: [!Sub ${ProjectName}-ci]) must be resolved and held to rule 4. */
    expect_fixture_violation("deploy/check/testdata/ci_reader_by_name.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    /* D9: an operator INLINE policy that lists another project's bucket is a
     * rule-2 violation just like a resource-level attached policy. */
    expect_fixture_violation("deploy/check/testdata/operator_inline_policy_other_bucket.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[1],
                             "otherproject-artifacts");

    /* N1 (D12): CI identity INLINE Policies are read grants and are held to
     * rule 4; PutObject on the own object ARN is a violation. */
    expect_fixture_violation("deploy/check/testdata/ci_inline_putobject.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    /* N1 (D12): CI identity inline GetObject on another project bucket. */
    expect_fixture_violation("deploy/check/testdata/ci_inline_other_bucket.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[3],
                             "otherproject-artifacts");

    /* N2 (D13): a policy attached to a CI-named GROUP by logical id, plus the
     * UserToGroupAddition that makes the CI user a member. */
    expect_fixture_violation("deploy/check/testdata/ci_reader_group_by_ref.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    /* N2 (D13): a policy attached to a CI-named ROLE by logical id. */
    expect_fixture_violation("deploy/check/testdata/ci_reader_role_by_ref.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    /* N3 (D14): the decoy `${ProjectName}-ci-tools` must not be treated as the
     * CI identity in either direction: its PutObject is not a rule-4 grant and
     * the real `${ProjectName}-ci` reader (benign here) is still the one
     * inspected. Exact name equality is required. */
    expect_fixture_clean("deploy/check/testdata/ci_decoy_identity.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);

    /* N4 (D15): a conditional inline Policies element is not a literal
     * PolicyDocument, so it fails closed instead of being skipped. */
    expect_fixture_violation("deploy/check/testdata/operator_policies_if_wrapped.yaml",
                             TC_MODE_OPERATOR,
                             "operator inline policy entry uses an unsupported intrinsic shape",
                             "Fn::If");

    /* N5 (D16): NotResource is a negated form the scope rules do not model; it
     * fails closed rather than being ignored. */
    expect_fixture_violation("deploy/check/testdata/notresource_statement.yaml",
                             TC_MODE_OPERATOR, "unsupported negated form",
                             "NotResource");

    /* D17 (F1a): a legitimate short-form !Join identity name resolves exactly
     * and is not falsely rejected; it is not the CI identity. */
    expect_fixture_clean("deploy/check/testdata/operator_join_identity_name.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);
    /* D17 (F1b): a CI identity named by short-form !Join is resolved and its
     * over-broad inline reader is caught by rule 4. */
    expect_fixture_violation("deploy/check/testdata/ci_join_identity_name.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    /* D18 (F2): CI membership through Properties.Groups with a !Ref group. */
    expect_fixture_violation("deploy/check/testdata/ci_groups_membership.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    /* D19 (F3): a Groups entry given as a literal group name. */
    expect_fixture_violation("deploy/check/testdata/ci_groups_literal_name.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    /* D19 (F3): a literal UserToGroupAddition.GroupName. */
    expect_fixture_violation("deploy/check/testdata/ci_usertogroup_literal_groupname.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    /* D20/D24 (F4): an identity name that cannot be statically resolved fails
     * closed, and the diagnostic states the policy explicitly. */
    expect_fixture_violation("deploy/check/testdata/ci_identity_name_param.yaml",
                             TC_MODE_OPERATOR,
                             "IAM identity CiUser name must be statically resolvable",
                             NULL);
    expect_fixture_violation("deploy/check/testdata/ci_identity_name_submap.yaml",
                             TC_MODE_OPERATOR,
                             "IAM identity CiUser name must be statically resolvable",
                             NULL);
    expect_fixture_violation("deploy/check/testdata/ci_identity_name_importvalue.yaml",
                             TC_MODE_OPERATOR,
                             "IAM identity CiUser name must be statically resolvable",
                             NULL);
    expect_fixture_violation("deploy/check/testdata/ci_identity_name_getatt.yaml",
                             TC_MODE_OPERATOR,
                             "IAM identity CiUser name must be statically resolvable",
                             NULL);

    /* D23 (F6a): a scalar !Sub with an unknown ${CiSuffix} variable is
     * unresolved, so its over-broad non-canonical reader cannot escape. */
    expect_fixture_violation("deploy/check/testdata/ci_identity_sub_unknown_var.yaml",
                             TC_MODE_OPERATOR,
                             "IAM identity CiUser name must be statically resolvable",
                             NULL);
    /* D23 (F6b): a legitimate !Sub using only ${ProjectName} resolves clean. */
    expect_fixture_clean("deploy/check/testdata/ci_identity_sub_known_var.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);
    /* D25 (F6c): an unresolved !Ref parameter in Groups fails closed. */
    expect_fixture_violation("deploy/check/testdata/ci_membership_unresolved_ref.yaml",
                             TC_MODE_OPERATOR,
                             "IAM membership entry must be statically resolvable",
                             NULL);

    /* D27 (i): a property-level intrinsic MAP in a membership section must fail
     * closed, not be skipped by the scalar-only walk. WriterGroup carries an
     * inline PutObject, so silently skipping the joined group would hide it. */
    expect_fixture_violation("deploy/check/testdata/ci_groups_if_wrapped.yaml",
                             TC_MODE_OPERATOR,
                             "must be a plain list of statically resolvable entries",
                             "Properties.Groups");
    /* D27 (i): Groups given as a short-form !Ref to a parameter is an
     * intrinsic, not a plain list, and fails closed. */
    expect_fixture_violation("deploy/check/testdata/ci_groups_list_param.yaml",
                             TC_MODE_OPERATOR,
                             "must be a plain list of statically resolvable entries",
                             "Properties.Groups");
    /* D27 (ii): UserToGroupAddition.Users as an intrinsic MAP must not skip the
     * whole addition (and its GroupName) silently. */
    expect_fixture_violation("deploy/check/testdata/ci_usertogroup_users_if.yaml",
                             TC_MODE_OPERATOR,
                             "must be a plain list of statically resolvable entries",
                             "UserToGroupAddition Properties.Users");
    /* D27 (iii): a CI-reader policy's Users section as an intrinsic MAP must
     * fail closed in the attachment paths rather than being skipped. */
    expect_fixture_violation("deploy/check/testdata/ci_reader_attach_if_wrapped.yaml",
                             TC_MODE_OPERATOR,
                             "must be a plain list of statically resolvable entries",
                             "IAM policy Users section");

    /* D29: a plain-sequence UserToGroupAddition.Users section whose ENTRY is an
     * intrinsic (!If) or a nested list must fail closed, not be silently
     * treated as "not CI" and skipped. WriterGroup's inline PutObject is only
     * reachable through that membership, so skipping it would hide a rule-4
     * grant. */
    static const char *const entry_must_resolve =
        "UserToGroupAddition Properties.Users entry must be statically resolvable";
    expect_fixture_violation("deploy/check/testdata/ci_usertogroup_users_if_entry.yaml",
                             TC_MODE_OPERATOR, entry_must_resolve,
                             "intrinsic or nested forms cannot be checked");
    expect_fixture_violation(
        "deploy/check/testdata/ci_usertogroup_users_nested_list.yaml",
        TC_MODE_OPERATOR, entry_must_resolve,
        "intrinsic or nested forms cannot be checked");
    /* D29 (no false rejection): a !Ref ENTRY to an existing non-CI user is a
     * legitimate principal. */
    expect_fixture_clean("deploy/check/testdata/ci_usertogroup_users_nonci_ref.yaml",
                         TC_MODE_OPERATOR, scope_diagnostics, scope_diagnostic_count);

    /* D21 (F5): second inline entry after a compliant one, CI-named Group and
     * Role inline policies, NotAction, unresolved principals in all three
     * attachment sections, long-form Fn::Join, and decoy enforcement. */
    expect_fixture_violation("deploy/check/testdata/ci_inline_second_violation.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    expect_fixture_violation("deploy/check/testdata/ci_group_inline_policy.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    expect_fixture_violation("deploy/check/testdata/ci_role_inline_policy.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    expect_fixture_violation("deploy/check/testdata/ci_notaction.yaml",
                             TC_MODE_OPERATOR, "unsupported negated form", "NotAction");
    expect_fixture_violation("deploy/check/testdata/ci_unresolved_principal.yaml",
                             TC_MODE_OPERATOR,
                             "does not resolve to a User/Role/Group resource",
                             "Users entry !Ref CiNameParam");
    expect_fixture_violation("deploy/check/testdata/ci_unresolved_principal.yaml",
                             TC_MODE_OPERATOR,
                             "does not resolve to a User/Role/Group resource",
                             "Roles entry !Ref CiRoleParam");
    expect_fixture_violation("deploy/check/testdata/ci_unresolved_principal.yaml",
                             TC_MODE_OPERATOR,
                             "does not resolve to a User/Role/Group resource",
                             "Groups entry !Ref CiGroupParam");
    expect_fixture_violation("deploy/check/testdata/ci_join_identity_longform.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");
    expect_fixture_violation("deploy/check/testdata/ci_decoy_enforced.yaml",
                             TC_MODE_OPERATOR, scope_diagnostics[2], "s3:PutObject");

    if (g_failures != 0) {
        fprintf(stderr, "%d/%d checks failed\n", g_failures, g_checks);
        return 1;
    }
    printf("template_check_test: %d checks passed\n", g_checks);
    return 0;
}
