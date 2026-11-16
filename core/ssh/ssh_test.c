/*
 * ssh_test.c — unit tests for core/ssh (spec §4 ssh argv contract).
 *
 * Covers the exact shared option set (golden argv), sentinel parsing, the
 * exit-255 reconnect-once rule, a plain non-zero remote exit, timeout with
 * process-group SIGTERM, and the SIGTERM→5 s→SIGKILL escalation. Commands used
 * by exec tests are `/bin/sh` so no ssh daemon is required.
 */

#include "ssh.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static void expect_argv(char **actual, const char *const *expected,
                        const char *label) {
    size_t index = 0;

    if (actual == NULL) {
        fprintf(stderr, "FAIL %s: argv is NULL\n", label);
        failures++;
        return;
    }
    while (expected[index] != NULL) {
        if (actual[index] == NULL || strcmp(actual[index], expected[index]) != 0) {
            fprintf(stderr, "FAIL %s: argv[%zu] = %s, want %s\n", label, index,
                    actual[index] != NULL ? actual[index] : "(null)",
                    expected[index]);
            failures++;
            return;
        }
        index++;
    }
    if (actual[index] != NULL) {
        fprintf(stderr, "FAIL %s: unexpected extra argv[%zu] = %s\n", label,
                index, actual[index]);
        failures++;
    }
}

static void test_golden_argv(void) {
    sshc_options opts = {
        .identity = "/home/op/.ssh/id_demo",
        .known_hosts = "/state/stackctl/demo.us-east-1/known_hosts",
        .instance_id = "i-0123456789abcdef0",
        .strict_yes = 1,
        .port = 2222,
        .user = "ec2-user",
        .server_alive_interval = 15,
        .server_alive_count_max = 3,
    };
    const char *const ssh_operands[] = {"203.0.113.9", "sudo", "true"};
    const char *const scp_operands[] = {"/tmp/bundle.tar",
                                        "203.0.113.9:/tmp/bundle.tar"};
    const char *const options[] = {
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "UpdateHostKeys=no",
        "ControlMaster=no",
        "ControlPath=none",
        "UserKnownHostsFile=/state/stackctl/demo.us-east-1/known_hosts",
        "StrictHostKeyChecking=yes",
        "HostKeyAlias=i-0123456789abcdef0",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
        "Port=2222",
        "User=ec2-user",
    };
    char *expected_ssh[64];
    char *expected_scp[64];
    size_t count = 0;
    char **argv = NULL;

    expected_ssh[count++] = (char *)"ssh";
    expected_ssh[count++] = (char *)"-T";
    expected_scp[0] = (char *)"scp";
    {
        size_t scp_count = 1;

        for (size_t i = 0; i < sizeof options / sizeof options[0]; i++) {
            expected_ssh[count++] = (char *)"-o";
            expected_ssh[count++] = (char *)options[i];
            if (i == 1) {
                expected_ssh[count++] = (char *)"-i";
                expected_ssh[count++] = (char *)opts.identity;
            }
            expected_scp[scp_count++] = (char *)"-o";
            expected_scp[scp_count++] = (char *)options[i];
            if (i == 1) {
                expected_scp[scp_count++] = (char *)"-i";
                expected_scp[scp_count++] = (char *)opts.identity;
            }
        }
        for (size_t i = 0; i < 3; i++) {
            expected_ssh[count++] = (char *)ssh_operands[i];
        }
        expected_ssh[count] = NULL;
        expected_scp[scp_count++] = (char *)scp_operands[0];
        expected_scp[scp_count++] = (char *)scp_operands[1];
        expected_scp[scp_count] = NULL;
    }

    CHECK(sshc_build_argv(SSHC_KIND_SSH, &opts, ssh_operands, 3, &argv) == 0,
          "ssh argv builds");
    expect_argv(argv, (const char *const *)expected_ssh, "ssh golden argv");
    sshc_argv_free(argv);
    argv = NULL;

    CHECK(sshc_build_argv(SSHC_KIND_SCP, &opts, scp_operands, 2, &argv) == 0,
          "scp argv builds");
    expect_argv(argv, (const char *const *)expected_scp, "scp golden argv");
    sshc_argv_free(argv);
    argv = NULL;

    /* TOFU fallback: that single connection uses accept-new. */
    opts.strict_yes = 0;
    CHECK(sshc_build_argv(SSHC_KIND_SSH, &opts, ssh_operands, 3, &argv) == 0,
          "accept-new argv builds");
    if (argv != NULL) {
        int found = 0;

        for (size_t i = 0; argv[i] != NULL; i++) {
            if (strcmp(argv[i], "StrictHostKeyChecking=accept-new") == 0) {
                found = 1;
            }
            CHECK(strcmp(argv[i], "StrictHostKeyChecking=yes") != 0,
                  "accept-new replaces the strict value");
        }
        CHECK(found, "StrictHostKeyChecking=accept-new emitted");
    }
    sshc_argv_free(argv);
    argv = NULL;

    CHECK(sshc_build_argv(SSHC_KIND_SSH, NULL, NULL, 0, &argv) == EINVAL,
          "NULL options rejected");
    sshc_argv_free(NULL);
}

static void test_sentinel(void) {
    sshc_sentinel_spec spec = {.prefix = "STACKCTL_RC="};
    int remote_rc = -1;
    char *args[] = {"/bin/sh", "-c", "echo STACKCTL_RC=7", NULL};

    CHECK(sshc_exec(args, 10, &spec, &remote_rc) == 0, "sentinel exec succeeds");
    CHECK(remote_rc == 7, "sentinel value 7 parsed");

    remote_rc = -1;
    {
        char *overrides[] = {"/bin/sh", "-c",
                             "echo STACKCTL_RC=1; echo STACKCTL_RC=0; exit 9",
                             NULL};

        CHECK(sshc_exec(overrides, 10, &spec, &remote_rc) == 0,
              "sentinel exec succeeds despite child exit 9");
        CHECK(remote_rc == 0, "final-line sentinel wins over ssh exit code");
    }

    /* No sentinel: the child's own status is the remote status. */
    remote_rc = -1;
    {
        char *args3[] = {"/bin/sh", "-c", "exit 3", NULL};

        CHECK(sshc_exec(args3, 10, &spec, &remote_rc) == 0,
              "no-sentinel exec succeeds");
        CHECK(remote_rc == 3, "child exit 3 reported");
    }

    /* No sentinel at all (spec NULL) still reports the exit code. */
    remote_rc = -1;
    {
        char *args4[] = {"/bin/sh", "-c", "exit 4", NULL};

        CHECK(sshc_exec(args4, 10, NULL, &remote_rc) == 0,
              "NULL sentinel spec accepted");
        CHECK(remote_rc == 4, "child exit 4 reported");
    }
}

static void test_reconnect(void) {
    sshc_sentinel_spec no_reconnect = {.prefix = "STACKCTL_RC="};
    sshc_sentinel_spec reconnect = {.prefix = "STACKCTL_RC=",
                                    .remote_rc_path = "/run/stackctl-setup/rc",
                                    .reconnect_argv = NULL};
    char *reader[] = {"/bin/sh", "-c", "printf '42\\n'", NULL};
    char *args255[] = {"/bin/sh", "-c", "exit 255", NULL};
    int remote_rc = -1;

    CHECK(sshc_exec(args255, 10, &no_reconnect, &remote_rc) == ENOTCONN,
          "exit 255 without sentinel is a transport failure");
    CHECK(sshc_exec(args255, 10, NULL, &remote_rc) == ENOTCONN,
          "exit 255 without spec is a transport failure");

    reconnect.reconnect_argv = reader;
    remote_rc = -1;
    CHECK(sshc_exec(args255, 10, &reconnect, &remote_rc) == 0,
          "exit 255 reconnect-once succeeds");
    CHECK(remote_rc == 42, "reconnect reads the remote rc value");
}

static void test_timeout(void) {
    sshc_sentinel_spec spec = {.prefix = "STACKCTL_RC="};
    int remote_rc = -1;
    char *slow[] = {"/bin/sh", "-c", "sleep 30", NULL};

    CHECK(sshc_exec(slow, 1, &spec, &remote_rc) == ETIMEDOUT,
          "timeout returns ETIMEDOUT");

    /* Child ignores SIGTERM: escalation to SIGKILL after the 5 s grace. */
    {
        char *stubborn[] = {"/bin/sh", "-c",
                            "trap '' TERM; while :; do sleep 1; done", NULL};

        CHECK(sshc_exec(stubborn, 1, &spec, &remote_rc) == ETIMEDOUT,
              "ignored SIGTERM still ends in ETIMEDOUT via SIGKILL");
    }
}

static int g_abort;
static int test_abort_check(void *user) {
    (void)user;
    return g_abort;
}

static void test_abort_hook(void) {
    sshc_sentinel_spec spec = {.prefix = "STACKCTL_RC="};
    int remote_rc = -1;
    char *slow[] = {"/bin/sh", "-c", "sleep 30", NULL};

    /* Unset hook: the child is allowed to finish normally. */
    g_abort = 0;
    sshc_set_abort_hook(NULL, NULL);
    {
        char *quick[] = {"/bin/sh", "-c", "printf 'STACKCTL_RC=0\\n'", NULL};

        CHECK(sshc_exec(quick, 10, &spec, &remote_rc) == 0,
              "no abort hook: exec completes");
    }

    /*
     * A set hook aborts the running child: the process group is torn down and
     * sshc_exec reports EINTR rather than the child's own status.
     */
    g_abort = 1;
    sshc_set_abort_hook(test_abort_check, NULL);
    CHECK(sshc_exec(slow, 30, &spec, &remote_rc) == EINTR,
          "abort hook returns EINTR");
    sshc_set_abort_hook(NULL, NULL);
}

static int progress_calls;
static int progress_last_elapsed;

static void count_progress(void *user, int elapsed_sec) {
    (void)user;
    progress_calls++;
    progress_last_elapsed = elapsed_sec;
}

static void test_progress_hook(void) {
    int remote_rc = -1;
    char *slow[] = {"/bin/sh", "-c", "sleep 0.3", NULL};
    char *quick[] = {"/bin/sh", "-c", "exit 0", NULL};

    /* Interval 0 is the test seam: report on every poll of a running child. */
    progress_calls = 0;
    progress_last_elapsed = -1;
    sshc_set_progress_hook(count_progress, NULL, 0);
    CHECK(sshc_exec(slow, 10, NULL, &remote_rc) == 0,
          "progress exec completes");
    CHECK(progress_calls >= 2, "a long-running child reports progress repeatedly");
    CHECK(progress_last_elapsed >= 0, "progress carries a non-negative elapsed time");

    /* Cleared hook: a short child produces no further reports. */
    sshc_set_progress_hook(NULL, NULL, 0);
    progress_calls = 0;
    CHECK(sshc_exec(quick, 10, NULL, &remote_rc) == 0,
          "exec after clearing the progress hook completes");
    CHECK(progress_calls == 0, "cleared progress hook stays silent");

    /* A positive interval suppresses the immediate report for a fast child. */
    progress_calls = 0;
    sshc_set_progress_hook(count_progress, NULL, 30);
    CHECK(sshc_exec(quick, 10, NULL, &remote_rc) == 0,
          "interval exec completes");
    CHECK(progress_calls == 0, "positive interval does not fire before it elapses");
    sshc_set_progress_hook(NULL, NULL, 0);
}

int main(void) {
    test_golden_argv();
    test_sentinel();
    test_reconnect();
    test_timeout();
    test_abort_hook();
    test_progress_hook();

    if (failures != 0) {
        fprintf(stderr, "ssh_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
