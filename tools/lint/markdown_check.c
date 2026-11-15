/*
 * markdown_check — a small, dependency-free Markdown lint used by
 * //tools/lint:lint-markdown.
 *
 * It enforces the conservative subset of markdownlint rules that matters for
 * this repository:
 *   - no tab characters,
 *   - no CRLF line endings,
 *   - no trailing whitespace beyond a two-space hard line break,
 *   - ATX headings have a space after the leading '#' run,
 *   - prose lines are at most 120 columns,
 *   - a non-empty file ends with a newline.
 *
 * Exit codes: 0 clean, 1 violations found, 2 usage/IO error.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_COLUMNS 120
#define MAX_HEADING_INDENT 3

static int g_violations;

static void report(const char *path, unsigned long line, const char *message) {
    fprintf(stderr, "%s:%lu: %s\n", path, line, message);
    g_violations++;
}

static int is_blank(const char *s) {
    for (; *s != '\0'; s++) {
        if (*s != ' ' && *s != '\t' && *s != '\n' && *s != '\r') {
            return 0;
        }
    }
    return 1;
}

static int is_fence(const char *line) {
    int indent = 0;
    while (line[indent] == ' ') {
        indent++;
    }
    return strncmp(line + indent, "```", 3) == 0 || strncmp(line + indent, "~~~", 3) == 0;
}

static void check_tabs(const char *path, unsigned long number, const char *line) {
    if (strchr(line, '\t') != NULL) {
        report(path, number, "tab character is not allowed");
    }
}

static void check_trailing_space(const char *path, unsigned long number, char *line) {
    size_t len = strlen(line);
    if (len == 0 || line[len - 1] != '\n') {
        return;
    }
    len--;
    if (len > 0 && line[len - 1] == '\r') {
        report(path, number, "CRLF line ending (use LF)");
        len--;
    }
    size_t spaces = 0;
    while (len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\t')) {
        if (line[len - 1] == '\t') {
            report(path, number, "trailing tab character");
            return;
        }
        spaces++;
        len--;
    }
    if (spaces > 2) {
        report(path, number, "trailing whitespace (more than a two-space hard break)");
    }
}

static void check_heading(const char *path, unsigned long number, const char *line) {
    int indent = 0;
    while (line[indent] == ' ') {
        indent++;
    }
    if (indent > MAX_HEADING_INDENT || line[indent] != '#') {
        return;
    }
    int hashes = 0;
    while (line[indent + hashes] == '#') {
        hashes++;
    }
    if (hashes > 6) {
        report(path, number, "ATX heading has more than six '#' markers");
        return;
    }
    char after = line[indent + hashes];
    if (after != '\0' && after != '\n' && after != ' ') {
        report(path, number, "ATX heading needs a space after the '#' run");
    }
}

static void check_width(const char *path, unsigned long number, const char *line) {
    size_t len = strcspn(line, "\r\n");
    if (len > MAX_LINE_COLUMNS) {
        report(path, number, "line exceeds 120 columns");
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
    int in_fence = 0;
    char last = '\0';
    ssize_t read;

    while ((read = getline(&line, &capacity, file)) != -1) {
        number++;
        last = line[read - 1];

        check_tabs(path, number, line);
        check_trailing_space(path, number, line);

        if (is_fence(line)) {
            in_fence = !in_fence;
            free(line);
            line = NULL;
            continue;
        }
        if (!in_fence && !is_blank(line)) {
            check_heading(path, number, line);
            check_width(path, number, line);
        }
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
        fprintf(stderr, "usage: markdown_check FILE...\n");
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
