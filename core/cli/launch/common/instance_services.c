/*
 * instance_services.c — production wiring of the injectable services vtable,
 * plus the ssh-keyscan adapter (fork/exec; stackctl never links libssh).
 */

#include "instance.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int instance_services_open(instance_services *svc, const char *project,
                           const char *region) {
    int rc;

    if (svc == NULL || project == NULL || region == NULL) {
        return EINVAL;
    }
    memset(svc, 0, sizeof *svc);
    rc = aws_init(&svc->aws, project);
    if (rc != 0) {
        return rc;
    }
    /* Long-running waiters must answer SIGINT/SIGTERM. */
    aws_set_abort_hook(svc->aws, cli_abort_check, NULL);
    rc = ec2_client_init(&svc->ec2, svc->aws, region);
    if (rc != 0) {
        instance_services_close(svc);
        return rc;
    }
    rc = ssm_client_init(&svc->ssm, svc->aws, region);
    if (rc != 0) {
        instance_services_close(svc);
        return rc;
    }
    rc = cfn_client_create(&svc->cfn, svc->aws);
    if (rc != 0) {
        instance_services_close(svc);
        return rc;
    }
    rc = s3_client_init(&svc->s3, svc->aws, region);
    if (rc != 0) {
        instance_services_close(svc);
        return rc;
    }

    svc->ec2_run_instances = ec2_run_instances;
    svc->ec2_describe_instances = ec2_describe_instances;
    svc->ec2_describe_images = ec2_describe_images;
    svc->ec2_terminate_instances = ec2_terminate_instances;
    svc->ec2_wait_running = ec2_wait_running_with_public_ip;
    svc->ec2_wait_terminated = ec2_wait_terminated;
    svc->ec2_get_console_output = ec2_get_console_output;

    svc->cfn_describe_stacks = cfn_describe_stacks;
    svc->ssm_get_parameter = ssm_get_parameter;
    svc->s3_head_object = s3_head_object;
    svc->s3_list_objects = s3_list_objects_v2;
    svc->s3_get_object = s3_get_object;

    svc->dns_a_record = dns_a_record;
    svc->dns_record_exists = dns_record_exists;
    svc->ddns_update = ddns_update;
    svc->ddns_ip_echo = ddns_ip_echo;

    svc->keyscan = instance_keyscan_exec;
    svc->ssh_exec = sshc_exec;
    svc->scp_exec = sshc_exec;

    svc->kh_pin = kh_pin;
    svc->kh_bound = kh_bound;
    svc->kh_forget = kh_forget;
    svc->tool_available = instance_tool_available;
    svc->iam_get_caller_identity = iam_get_caller_identity;
    return 0;
}

void instance_services_close(instance_services *svc) {
    if (svc == NULL) {
        return;
    }
    s3_client_free(svc->s3);
    cfn_client_destroy(svc->cfn);
    ssm_client_free(svc->ssm);
    ec2_client_free(svc->ec2);
    aws_free(svc->aws);
    memset(svc, 0, sizeof *svc);
}

/*
 * Run `ssh-keyscan -t ed25519 -p <port> <ip>`, capture stdout and return the
 * first line that looks like a host-key line (`<host> <type> <blob>`). The
 * child's stderr is discarded (keyscan is chatty on a not-yet-listening sshd).
 */
int instance_keyscan_exec(const char *ip, int port, char **line_out) {
    int pipefd[2];
    pid_t pid;
    char buffer[8192];
    size_t used = 0;
    ssize_t got;
    int status = 0;
    char port_text[16];
    char *cursor;

    if (ip == NULL || line_out == NULL || port <= 0) {
        return EINVAL;
    }
    *line_out = NULL;
    if (pipe(pipefd) != 0) {
        return errno != 0 ? errno : EIO;
    }
    pid = fork();
    if (pid < 0) {
        int saved = errno;

        close(pipefd[0]);
        close(pipefd[1]);
        return saved != 0 ? saved : EIO;
    }
    if (pid == 0) {
        int devnull;

        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(pipefd[1]);
        snprintf(port_text, sizeof port_text, "%d", port);
        execlp("ssh-keyscan", "ssh-keyscan", "-t", "ed25519", "-p", port_text,
               ip, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    while (used + 1 < sizeof buffer) {
        got = read(pipefd[0], buffer + used, sizeof buffer - used - 1);
        if (got > 0) {
            used += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    close(pipefd[0]);
    (void)waitpid(pid, &status, 0);
    buffer[used] = '\0';

    /*
     * ssh-keyscan prints one or more `#` banner/comment lines before the key
     * line, so scan every line rather than trusting the first.
     */
    cursor = buffer;
    for (;;) {
        char *next = strchr(cursor, '\n');
        char *start = cursor;

        if (next != NULL) {
            *next = '\0';
        }
        while (*start == ' ' || *start == '\t' || *start == '\r') {
            start++;
        }
        if (*start != '\0' && *start != '#') {
            *line_out = strdup(start);
            if (*line_out == NULL) {
                return ENOMEM;
            }
            return 0;
        }
        if (next == NULL) {
            break;
        }
        cursor = next + 1;
    }
    return 0; /* no key produced yet */
}
