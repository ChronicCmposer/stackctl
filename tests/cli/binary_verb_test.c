/*
 * binary_verb_test.c — drive a real verb through the built `stackctl` binary.
 *
 * The binary is pointed at an in-test HTTP server over loopback with
 * STACKCTL_ENDPOINT_URL; the server answers the AWS Query calls `status`
 * makes (STS GetCallerIdentity, CloudFormation DescribeStacks, EC2
 * DescribeImages/DescribeInstances) with fixed XML. No external network, no
 * real credentials, no host tools beyond the binary itself.
 *
 * Asserts the process exit code and the stdout/stderr shape: stdout is the
 * documented JSON report, stderr is quiet and never leaks the access secret.
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY "test-secret-never-leaked"

static int failures;

#define CHECK(cond, message)                                                   \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", (message), __FILE__,         \
                    __LINE__);                                                 \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ---------------------------------------------------------------------- */
/* Temporary filesystem helpers (no host `rm`)                            */
/* ---------------------------------------------------------------------- */

static void write_text(const char *path, const char *text) {
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        exit(1);
    }
    if (fputs(text, file) == EOF) {
        perror(path);
        exit(1);
    }
    if (fclose(file) != 0) {
        perror(path);
        exit(1);
    }
}

static void make_executable(const char *path) {
    write_text(path, "");
    if (chmod(path, 0700) != 0) {
        perror(path);
        exit(1);
    }
}

static void remove_tree(const char *path) {
    struct stat st;
    DIR *dir;
    struct dirent *entry;

    if (lstat(path, &st) != 0) {
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        (void)unlink(path);
        return;
    }
    dir = opendir(path);
    if (dir != NULL) {
        while ((entry = readdir(dir)) != NULL) {
            char child[PATH_MAX];

            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            if (snprintf(child, sizeof child, "%s/%s", path, entry->d_name) >=
                (int)sizeof child) {
                continue;
            }
            remove_tree(child);
        }
        closedir(dir);
    }
    (void)rmdir(path);
}

/* ---------------------------------------------------------------------- */
/* Fake AWS endpoint                                                      */
/* ---------------------------------------------------------------------- */

static const char *RESP_STS =
    "<GetCallerIdentityResponse "
    "xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
    "<GetCallerIdentityResult>"
    "<Arn>arn:aws:iam::123456789012:user/demo</Arn>"
    "<UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>"
    "</GetCallerIdentityResult>"
    "<ResponseMetadata><RequestId>sts-1</RequestId></ResponseMetadata>"
    "</GetCallerIdentityResponse>";

static const char *RESP_STACKS =
    "<DescribeStacksResponse "
    "xmlns=\"http://cloudformation.amazonaws.com/doc/2010-05-15/\">"
    "<DescribeStacksResult><Stacks><member>"
    "<StackId>arn:aws:cloudformation:us-east-1:123456789012:stack/"
    "demo-infra/abc</StackId>"
    "<StackName>demo-infra</StackName>"
    "<StackStatus>UPDATE_COMPLETE</StackStatus>"
    "<Parameters><member><ParameterKey>AmiIdAmd64</ParameterKey>"
    "<ParameterValue>ami-0123456789abcdef0</ParameterValue></member>"
    "</Parameters>"
    "</member></Stacks></DescribeStacksResult>"
    "<ResponseMetadata><RequestId>cfn-1</RequestId></ResponseMetadata>"
    "</DescribeStacksResponse>";

static const char *RESP_IMAGES =
    "<DescribeImagesResponse><imagesSet><item>"
    "<imageId>ami-0123456789abcdef0</imageId>"
    "<imageState>available</imageState>"
    "<name>deep-learning-amd64</name>"
    "<architecture>x86_64</architecture>"
    "<rootDeviceName>/dev/xvda</rootDeviceName>"
    "</item></imagesSet></DescribeImagesResponse>";

static const char *RESP_INSTANCES =
    "<DescribeInstancesResponse><reservationSet/>"
    "</DescribeInstancesResponse>";

static const char *RESP_UNKNOWN =
    "<Response><ResponseMetadata><RequestId>unknown</RequestId>"
    "</ResponseMetadata></Response>";

static const char *response_for(const char *body) {
    if (strstr(body, "Action=GetCallerIdentity") != NULL) {
        return RESP_STS;
    }
    if (strstr(body, "Action=DescribeStacks") != NULL) {
        return RESP_STACKS;
    }
    if (strstr(body, "Action=DescribeImages") != NULL) {
        return RESP_IMAGES;
    }
    if (strstr(body, "Action=DescribeInstances") != NULL) {
        return RESP_INSTANCES;
    }
    return RESP_UNKNOWN;
}

static int listen_loopback(uint16_t *port_out) {
    struct sockaddr_in address;
    socklen_t length = sizeof address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;

    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse) != 0) {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(fd, 16) != 0 ||
        getsockname(fd, (struct sockaddr *)&address, &length) != 0) {
        close(fd);
        return -1;
    }
    *port_out = ntohs(address.sin_port);
    return fd;
}

/* Read one HTTP/1.1 request and answer it; returns 0 to continue serving. */
static int serve_one(int client) {
    char request[65536];
    size_t used = 0;
    long content_length = 0;
    char *header_end;
    const char *body;
    const char *response;
    char message[4096];
    int message_len;

    while (used + 1 < sizeof request) {
        ssize_t got = recv(client, request + used, sizeof request - used - 1, 0);

        if (got <= 0) {
            return 0;
        }
        used += (size_t)got;
        request[used] = '\0';
        header_end = strstr(request, "\r\n\r\n");
        if (header_end != NULL) {
            char *length = strstr(request, "\r\nContent-Length:");
            size_t header_bytes = (size_t)(header_end + 4 - request);

            if (length == NULL) {
                length = strstr(request, "\r\ncontent-length:");
            }
            if (length != NULL && (size_t)(length - request) < header_bytes) {
                length += strlen("\r\nContent-Length:");
                content_length = strtol(length, NULL, 10);
            }
            if (used >= header_bytes + (size_t)(content_length > 0
                                                    ? content_length
                                                    : 0)) {
                break;
            }
        }
    }
    header_end = strstr(request, "\r\n\r\n");
    if (header_end == NULL) {
        return 0;
    }
    body = header_end + 4;
    response = response_for(body);
    message_len = snprintf(message, sizeof message,
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/xml\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n\r\n%s",
                           strlen(response), response);
    if (message_len > 0) {
        (void)send(client, message, (size_t)message_len, 0);
    }
    return 0;
}

static pid_t start_server(int listen_fd) {
    pid_t pid = fork();

    if (pid != 0) {
        return pid;
    }
    for (;;) {
        int client = accept(listen_fd, NULL, NULL);

        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            _exit(0);
        }
        (void)serve_one(client);
        close(client);
    }
}

/* ---------------------------------------------------------------------- */
/* Fixture                                                                */
/* ---------------------------------------------------------------------- */

typedef struct fixture {
    char root[PATH_MAX];
    char config_dir[PATH_MAX];
    char bin_dir[PATH_MAX];
    char home[PATH_MAX];
    char state[PATH_MAX];
    char identity[PATH_MAX];
    char stdout_path[PATH_MAX];
    char stderr_path[PATH_MAX];
    char binary[PATH_MAX];
    int listen_fd;
    pid_t server;
} fixture;

static const char *ENV_BODY =
    "PROJECT=demo\n"
    "REGION=us-east-1\n"
    "ARCH=amd64\n"
    "SPOT_DEFAULT=false\n"
    "AMI_POLICY=pinned\n"
    "AMI_ID_AMD64=ami-0123456789abcdef0\n"
    "INSTANCE_TYPES_AMD64=g4dn.xlarge\n"
    "ROOT_VOLUME_SIZE=100\n"
    "KEY_NAME=demo-key\n"
    "SSH_IDENTITY=%s\n"
    "BUCKET_MODULES=artifact\n"
    "ENABLE_IMAGE_BUILDER=false\n"
    "SETUP_ENTRYPOINT=deploy.sh\n"
    "SSH_PORT=22\n"
    "SERVICE_UNIT=demo.service\n"
    "OPERATOR_CIDR=203.0.113.0/24\n"
    "INGRESS_TCP=443\n"
    "INGRESS_UDP=\n"
    "RELEASE_TARGETS=//app:deploy.tar.gz\n"
    "ENABLE_CI_USER=true\n";

static void locate_binary(char out[PATH_MAX]) {
    const char *srcdir = getenv("TEST_SRCDIR");
    const char *workspace = getenv("TEST_WORKSPACE");
    const char *suffix = "core/cli/dispatch/stackctl";
    static const char *const roots[] = {"_main", "stackctl"};

    if (srcdir != NULL && workspace != NULL) {
        if (snprintf(out, PATH_MAX, "%s/%s/%s", srcdir, workspace, suffix) <
                PATH_MAX &&
            access(out, X_OK) == 0) {
            return;
        }
    }
    if (srcdir != NULL) {
        for (size_t i = 0; i < sizeof roots / sizeof roots[0]; i++) {
            if (snprintf(out, PATH_MAX, "%s/%s/%s", srcdir, roots[i], suffix) <
                    PATH_MAX &&
                access(out, X_OK) == 0) {
                return;
            }
        }
    }
    fprintf(stderr, "cannot locate stackctl in runfiles\n");
    exit(1);
}

static void fixture_init(fixture *fx) {
    char template[] = "/tmp/stackctl-binary-XXXXXX";
    char *root = mkdtemp(template);
    char path[PATH_MAX];
    char env[4096];
    char credentials[PATH_MAX];

    memset(fx, 0, sizeof *fx);
    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(fx->root, sizeof fx->root, "%s", root);
    snprintf(fx->config_dir, sizeof fx->config_dir, "%s/deploy/aws", fx->root);
    snprintf(fx->bin_dir, sizeof fx->bin_dir, "%s/bin", fx->root);
    snprintf(fx->home, sizeof fx->home, "%s/home", fx->root);
    snprintf(fx->state, sizeof fx->state, "%s/state", fx->root);
    snprintf(fx->identity, sizeof fx->identity, "%s/id_demo", fx->root);
    snprintf(fx->stdout_path, sizeof fx->stdout_path, "%s/stdout", fx->root);
    snprintf(fx->stderr_path, sizeof fx->stderr_path, "%s/stderr", fx->root);
    locate_binary(fx->binary);

    snprintf(path, sizeof path, "%s/home", fx->root);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        perror(path);
        exit(1);
    }
    snprintf(path, sizeof path, "%s/.aws", fx->home);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        perror(path);
        exit(1);
    }
    snprintf(credentials, sizeof credentials, "%s/.aws/credentials", fx->home);
    write_text(credentials,
               "[demo]\n"
               "aws_access_key_id = AKIAEXAMPLE\n"
               "aws_secret_access_key = " SECRET_KEY "\n");

    snprintf(path, sizeof path, "%s/deploy", fx->root);
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        perror(path);
        exit(1);
    }
    if (mkdir(fx->config_dir, 0700) != 0 && errno != EEXIST) {
        perror(fx->config_dir);
        exit(1);
    }
    snprintf(path, sizeof path, "%s/MODULE.bazel", fx->root);
    write_text(path, "");
    snprintf(path, sizeof path, "%s/.env", fx->config_dir);
    snprintf(env, sizeof env, ENV_BODY, fx->identity);
    write_text(path, env);
    write_text(fx->identity, "");

    if (mkdir(fx->bin_dir, 0700) != 0 && errno != EEXIST) {
        perror(fx->bin_dir);
        exit(1);
    }
    snprintf(path, sizeof path, "%s/ssh", fx->bin_dir);
    make_executable(path);
    snprintf(path, sizeof path, "%s/scp", fx->bin_dir);
    make_executable(path);
    snprintf(path, sizeof path, "%s/ssh-keyscan", fx->bin_dir);
    make_executable(path);
    /* status runs the bazel preflight; the fake PATH needs it present. */
    snprintf(path, sizeof path, "%s/bazel", fx->bin_dir);
    make_executable(path);
    if (mkdir(fx->state, 0700) != 0 && errno != EEXIST) {
        perror(fx->state);
        exit(1);
    }

    {
        uint16_t port = 0;

        fx->listen_fd = listen_loopback(&port);
        if (fx->listen_fd < 0) {
            perror("listen");
            exit(1);
        }
        fx->server = start_server(fx->listen_fd);
        {
            char url[128];
            snprintf(url, sizeof url, "http://127.0.0.1:%u", (unsigned)port);
            if (setenv("STACKCTL_ENDPOINT_URL", url, 1) != 0) {
                perror("setenv");
                exit(1);
            }
        }
    }
}

static void fixture_done(fixture *fx) {
    if (fx->server > 0) {
        (void)kill(fx->server, SIGTERM);
        (void)waitpid(fx->server, NULL, 0);
    }
    if (fx->listen_fd >= 0) {
        close(fx->listen_fd);
    }
    remove_tree(fx->root);
}

/* ---------------------------------------------------------------------- */
/* Driver                                                                 */
/* ---------------------------------------------------------------------- */

static int run_binary(fixture *fx) {
    int out = open(fx->stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int err = open(fx->stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    pid_t pid;
    int status = 0;

    if (out < 0 || err < 0) {
        perror("open");
        exit(1);
    }
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid == 0) {
        char *const argv[] = {fx->binary, "--project", fx->config_dir, "status",
                              "--json", NULL};
        char path[PATH_MAX];

        if (dup2(out, STDOUT_FILENO) < 0 || dup2(err, STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(out);
        close(err);
        snprintf(path, sizeof path, "%s", fx->bin_dir);
        if (setenv("PATH", path, 1) != 0 || setenv("HOME", fx->home, 1) != 0 ||
            setenv("XDG_STATE_HOME", fx->state, 1) != 0) {
            _exit(126);
        }
        execv(fx->binary, argv);
        _exit(127);
    }
    close(out);
    close(err);
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        exit(1);
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 128 + WTERMSIG(status);
}

static char *read_file(const char *path) {
    FILE *file = fopen(path, "r");
    long size;
    char *buffer;

    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    buffer = calloc((size_t)size + 1, 1);
    if (buffer != NULL && fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        buffer = NULL;
    }
    fclose(file);
    return buffer;
}

int main(void) {
    fixture fx;
    int rc;
    char *out;
    char *err;

    fixture_init(&fx);
    rc = run_binary(&fx);
    out = read_file(fx.stdout_path);
    err = read_file(fx.stderr_path);

    CHECK(rc == 0, "status verb exits 0");
    CHECK(out != NULL, "stdout captured");
    if (out != NULL) {
        char *start = out;

        while (*start == ' ' || *start == '\n' || *start == '\t') {
            start++;
        }
        CHECK(*start == '{', "stdout is a JSON object");
        CHECK(strstr(out, "\"schema_version\"") != NULL,
              "stdout carries the report schema");
        CHECK(strstr(out, "\"instances\"") != NULL,
              "stdout carries the instances array");
    }
    CHECK(err != NULL, "stderr captured");
    if (err != NULL) {
        CHECK(strstr(err, SECRET_KEY) == NULL,
              "stderr never leaks the access secret");
        CHECK(strstr(err, "cannot ") == NULL,
              "stderr carries no failure diagnostics");
    }

    if (failures != 0) {
        fprintf(stderr, "binary_verb_test: exit=%d\nstdout:\n%s\nstderr:\n%s\n",
                rc, out != NULL ? out : "(null)",
                err != NULL ? err : "(null)");
    }
    free(out);
    free(err);
    fixture_done(&fx);
    if (failures != 0) {
        fprintf(stderr, "binary_verb_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("binary_verb_test: ok\n");
    return 0;
}
