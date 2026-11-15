/*
 * yaml_check — a small, dependency-free YAML lint used by
 * //tools/lint:lint-yaml.
 *
 * Substituted for yamllint because no hermetic Python toolchain is pinned in
 * this run (Amendment 4 requires Bazel-managed tooling only). It enforces the
 * conservative subset that matters here:
 *   - no tab characters (YAML forbids tab indentation),
 *   - no CRLF line endings,
 *   - no trailing whitespace,
 *   - a non-empty file ends with a newline.
 *
 * Exit codes: 0 clean, 1 violations found, 2 usage/IO error.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_violations;

static void report(const char *path, unsigned long line, const char *message) {
    fprintf(stderr, "%s:%lu: %s\n", path, line, message);
    g_violations++;
}

static void check_line(const char *path, unsigned long number, const char *line) {
    if (strchr(line, '\t') != NULL) {
        report(path, number, "tab character is not allowed in YAML");
    }

    size_t len = strlen(line);
    if (len == 0 || line[len - 1] != '\n') {
        return;
    }
    len--;
    if (len > 0 && line[len - 1] == '\r') {
        report(path, number, "CRLF line ending (use LF)");
        len--;
    }
    if (len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\t')) {
        report(path, number, "trailing whitespace");
    }
}

static int check_file(const char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "%s: cannot open: %s\n", path, strerror(errno));
        return 2;
    }

    char *line = NULL;
    size_t capacity = 0;
    unsigned long number = 0;
    char last = '\0';
    ssize_t read;

    while ((read = getline(&line, &capacity, file)) != -1) {
        number++;
        last = line[read - 1];
        check_line(path, number, line);
    }

    if (number > 0 && last != '\n') {
        report(path, number, "file does not end with a newline");
    }

    free(line);
    fclose(file);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: yaml_check FILE...\n");
        return 2;
    }

    int io_error = 0;
    for (int i = 1; i < argc; i++) {
        if (check_file(argv[i]) != 0) {
            io_error = 1;
        }
    }

    if (io_error) {
        return 2;
    }
    return g_violations > 0 ? 1 : 0;
}
