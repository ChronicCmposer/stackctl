/*
 * cli_output.c — stdout/stderr, table/JSON, confirmation, redaction, usage and
 * exit-code helpers.
 *
 * Stream discipline: stdout is verb output only; warnings, prompts and errors
 * go to stderr so `--json` output stays parseable.
 */

#include "cli.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "yyjson.h"

/* ------------------------------------------------------------------------- */
/* Basic streams                                                             */
/* ------------------------------------------------------------------------- */

void cli_out(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

void cli_err(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

void cli_warn(cli_ctx *ctx, const char *fmt, ...) {
    va_list args;

    (void)ctx;
    fputs("stackctl: warning: ", stderr);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

int cli_fail(cli_ctx *ctx, int code, const char *fmt, ...) {
    va_list args;

    (void)ctx;
    fputs("stackctl: ", stderr);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    return code;
}

int cli_rc_to_exit(int rc) {
    if (rc == 0) {
        return CLI_EXIT_OK;
    }
    switch (rc) {
    case EINVAL:
    case ENOENT:
    case ETIMEDOUT:
    case EACCES:
    case EPERM:
    case ENOMEM:
        return CLI_EXIT_USAGE;
    default:
        return CLI_EXIT_AWS;
    }
}

/* ------------------------------------------------------------------------- */
/* Table                                                                     */
/* ------------------------------------------------------------------------- */

static const char *cell_text(const char *text) { return text != NULL ? text : ""; }

int cli_table_write(FILE *out, const cli_table *table) {
    size_t columns;
    size_t *widths;
    int rc = 0;

    if (out == NULL || table == NULL || table->header_count == 0) {
        return EINVAL;
    }
    if (table->headers == NULL) {
        return EINVAL;
    }
    if (table->row_count > 0 && table->cells == NULL) {
        return EINVAL;
    }

    columns = table->header_count;
    widths = calloc(columns, sizeof(*widths));
    if (widths == NULL) {
        return ENOMEM;
    }

    for (size_t c = 0; c < columns; c++) {
        widths[c] = strlen(cell_text(table->headers[c]));
    }
    for (size_t r = 0; r < table->row_count; r++) {
        for (size_t c = 0; c < columns; c++) {
            size_t width = strlen(cell_text(table->cells[r * columns + c]));
            if (width > widths[c]) {
                widths[c] = width;
            }
        }
    }

    for (size_t c = 0; c < columns; c++) {
        const char *text = cell_text(table->headers[c]);
        size_t width = strlen(text);

        if (fputs(text, out) == EOF) {
            rc = EIO;
            goto done;
        }
        if (c + 1 < columns) {
            for (size_t pad = width; pad < widths[c]; pad++) {
                fputc(' ', out);
            }
            fputs("  ", out);
        }
    }
    fputc('\n', out);

    for (size_t r = 0; r < table->row_count; r++) {
        for (size_t c = 0; c < columns; c++) {
            const char *text = cell_text(table->cells[r * columns + c]);
            size_t width = strlen(text);

            if (fputs(text, out) == EOF) {
                rc = EIO;
                goto done;
            }
            if (c + 1 < columns) {
                for (size_t pad = width; pad < widths[c]; pad++) {
                    fputc(' ', out);
                }
                fputs("  ", out);
            }
        }
        fputc('\n', out);
    }

done:
    free(widths);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* JSON                                                                      */
/* ------------------------------------------------------------------------- */

int cli_json_write(FILE *out, struct yyjson_mut_doc *doc) {
    char *text;
    int rc = 0;

    if (out == NULL || doc == NULL) {
        return EINVAL;
    }
    text = yyjson_mut_write(doc, YYJSON_WRITE_PRETTY, NULL);
    if (text == NULL) {
        return ENOMEM;
    }
    if (fputs(text, out) == EOF || fputc('\n', out) == EOF) {
        rc = EIO;
    }
    free(text);
    return rc;
}

int cli_json_emit(struct yyjson_mut_doc *doc) {
    return cli_json_write(stdout, doc);
}

/* ------------------------------------------------------------------------- */
/* Confirmation & TTY                                                        */
/* ------------------------------------------------------------------------- */

int cli_is_tty(FILE *stream) {
    int fd;

    if (stream == NULL) {
        return 0;
    }
    fd = fileno(stream);
    if (fd < 0) {
        return 0;
    }
    return isatty(fd) == 1;
}

int cli_confirm_stream(FILE *in, FILE *out, int interactive, int assume_yes,
                       const char *prompt) {
    char line[64];
    char *end;

    if (assume_yes != 0) {
        return CLI_CONFIRM_YES;
    }
    if (interactive == 0) {
        return CLI_CONFIRM_NONINTERACTIVE;
    }
    if (in == NULL) {
        return CLI_CONFIRM_EOF;
    }
    if (out != NULL && prompt != NULL) {
        fputs(prompt, out);
        fflush(out);
    }
    if (fgets(line, sizeof(line), in) == NULL) {
        return CLI_CONFIRM_EOF;
    }
    end = line + strlen(line);
    while (end > line && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    if (strcasecmp(line, "y") == 0 || strcasecmp(line, "yes") == 0) {
        return CLI_CONFIRM_YES;
    }
    return CLI_CONFIRM_NO;
}

int cli_confirm(cli_ctx *ctx, const char *prompt) {
    int assume_yes = ctx != NULL && cli_ctx_yes(ctx) != 0;

    return cli_confirm_stream(stdin, stderr, cli_is_tty(stdin), assume_yes,
                              prompt);
}

/* ------------------------------------------------------------------------- */
/* Secret redaction                                                          */
/* ------------------------------------------------------------------------- */

static int contains_ci(const char *text, size_t length, const char *needle) {
    size_t needle_len = strlen(needle);

    if (needle_len == 0 || needle_len > length) {
        return 0;
    }
    for (size_t i = 0; i + needle_len <= length; i++) {
        size_t j;

        for (j = 0; j < needle_len; j++) {
            if (tolower((unsigned char)text[i + j]) !=
                (unsigned char)needle[j]) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static int is_secret_name(const char *name, size_t length) {
    return contains_ci(name, length, "password") != 0 ||
           contains_ci(name, length, "secret") != 0 ||
           contains_ci(name, length, "token") != 0;
}

static int append_n(char *out, size_t capacity, size_t *used,
                    const char *text, size_t length) {
    if (*used + length + 1 > capacity) {
        return ERANGE;
    }
    if (length > 0) {
        memcpy(out + *used, text, length);
        *used += length;
    }
    out[*used] = '\0';
    return 0;
}

int cli_redact_args(const char *const *argv, size_t argc, char *out,
                    size_t out_size) {
    size_t used = 0;
    int first = 1;

    if (out == NULL || out_size == 0) {
        return EINVAL;
    }
    out[0] = '\0';
    if (argc > 0 && argv == NULL) {
        return EINVAL;
    }

    for (size_t i = 0; i < argc; i++) {
        const char *argument = argv[i] != NULL ? argv[i] : "";
        int rendered = 0;
        int rc = 0;

        if (!first) {
            rc = append_n(out, out_size, &used, " ", 1);
        }
        if (rc != 0) {
            memset(out, 0, out_size);
            return rc;
        }
        first = 0;

        if (strncmp(argument, "--", 2) == 0 && argument[2] != '\0') {
            const char *body = argument + 2;
            const char *equals = strchr(body, '=');
            size_t name_len = equals != NULL ? (size_t)(equals - body)
                                             : strlen(body);

            if (is_secret_name(body, name_len)) {
                rc = append_n(out, out_size, &used, "--", 2);
                if (rc == 0) {
                    rc = append_n(out, out_size, &used, body, name_len);
                }
                if (rc == 0) {
                    rc = append_n(out, out_size, &used, "=<redacted>", 11);
                }
                if (equals == NULL && i + 1 < argc) {
                    i++; /* hide the separate operand too */
                }
                rendered = 1;
            }
        } else {
            const char *equals = strchr(argument, '=');

            if (equals != NULL && equals != argument &&
                is_secret_name(argument, (size_t)(equals - argument))) {
                rc = append_n(out, out_size, &used, argument,
                              (size_t)(equals - argument));
                if (rc == 0) {
                    rc = append_n(out, out_size, &used, "=<redacted>", 11);
                }
                rendered = 1;
            }
        }

        if (!rendered) {
            rc = append_n(out, out_size, &used, argument, strlen(argument));
        }
        if (rc != 0) {
            memset(out, 0, out_size);
            return rc;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Usage                                                                     */
/* ------------------------------------------------------------------------- */

void cli_print_global_usage(FILE *out, const char *program) {
    const char *name = program != NULL ? program : "stackctl";

    if (out == NULL) {
        return;
    }
    fprintf(out,
            "Usage: %s [global flags] --project <config-dir> <verb> [flags]\n"
            "\n"
            "Global flags:\n"
            "  --project <dir>        project config directory (required)\n"
            "  --region <name>        load the .env.<name> region variant\n"
            "  --json                 machine-readable JSON on stdout\n"
            "  -y, --yes              assume yes for confirmation prompts\n"
            "  --dry-run              preview changes without applying\n"
            "  --lock-timeout <sec>   wait at most <sec> for the project lock\n"
            "  -h, --help             show help\n"
            "  --version              show version\n",
            name);
}

void cli_print_command_usage(FILE *out, const char *program,
                             const cli_command *command,
                             const cli_option_spec *options,
                             size_t option_count) {
    const char *name = program != NULL ? program : "stackctl";

    if (out == NULL) {
        return;
    }
    if (command == NULL) {
        cli_print_global_usage(out, name);
        return;
    }
    fprintf(out, "Usage: %s [global flags] %s\n", name,
            command->usage != NULL ? command->usage : command->name);
    if (command->summary != NULL) {
        fprintf(out, "\n%s\n", command->summary);
    }
    if (options != NULL && option_count > 0) {
        fputs("\nOptions:\n", out);
        for (size_t i = 0; i < option_count; i++) {
            const cli_option_spec *option = &options[i];

            fputs("  ", out);
            if (option->short_name != 0) {
                fprintf(out, "-%c, ", option->short_name);
            }
            fprintf(out, "--%s", option->name);
            if (option->takes_value != 0) {
                fprintf(out, " %s",
                        option->metavar != NULL ? option->metavar : "<value>");
            }
            if (option->help != NULL) {
                fprintf(out, "   %s", option->help);
            }
            fputc('\n', out);
        }
    }
}
