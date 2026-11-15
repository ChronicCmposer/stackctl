/*
 * cli_args.c — deterministic argv parsing and global-flag extraction.
 *
 * Parsing is intentionally strict and side-effect free: no getopt globals, no
 * locale-sensitive conversion, no mutation of argv. All returned strings point
 * into the caller's argv; only the result arrays are heap-owned.
 */

#include "cli.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static const cli_option_spec *find_long(const cli_option_spec *specs,
                                        size_t count, const char *name,
                                        size_t name_len) {
    for (size_t i = 0; i < count; i++) {
        if (strlen(specs[i].name) == name_len &&
            strncmp(specs[i].name, name, name_len) == 0) {
            return &specs[i];
        }
    }
    return NULL;
}

static const cli_option_spec *find_short(const cli_option_spec *specs,
                                         size_t count, char short_name) {
    for (size_t i = 0; i < count; i++) {
        if (specs[i].short_name != 0 && specs[i].short_name == short_name) {
            return &specs[i];
        }
    }
    return NULL;
}

static size_t spec_index(const cli_option_spec *specs,
                         const cli_option_spec *spec) {
    return (size_t)(spec - specs);
}

static void args_clear(cli_args *args) {
    if (args == NULL) {
        return;
    }
    memset(args, 0, sizeof(*args));
}

static void release_arrays(cli_option_value *values, size_t value_count,
                           const char **positionals) {
    if (values != NULL) {
        for (size_t i = 0; i < value_count; i++) {
            free((void *)values[i].values);
        }
        free(values);
    }
    free((void *)positionals);
}

/* Record one occurrence of `spec` with `value` (NULL for boolean flags). */
static int record_option(cli_option_value *entry, const cli_option_spec *spec,
                         const char *value) {
    if (spec->takes_value != 0) {
        if (spec->repeatable == 0 && entry->present != 0) {
            return EINVAL;
        }
        if (spec->repeatable != 0) {
            const char **grown = realloc((void *)entry->values,
                                         (entry->value_count + 1) *
                                             sizeof(*entry->values));
            if (grown == NULL) {
                return ENOMEM;
            }
            grown[entry->value_count] = value;
            entry->values = grown;
            entry->value_count++;
        }
        entry->value = value;
    }
    /* Boolean flags are idempotent: repeated -y/--json is accepted. */
    entry->present = 1;
    entry->count++;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Verb option parsing                                                       */
/* ------------------------------------------------------------------------- */

int cli_args_parse(int argc, char **argv, const cli_option_spec *specs,
                   size_t spec_count, cli_args *out) {
    if (out == NULL) {
        return EINVAL;
    }
    args_clear(out);
    if (argc < 0) {
        return EINVAL;
    }
    if (argc > 0 && argv == NULL) {
        return EINVAL;
    }
    if (spec_count > 0 && specs == NULL) {
        return EINVAL;
    }

    cli_option_value *values = NULL;
    const char **positionals = NULL;
    size_t positional_count = 0;

    if (spec_count > 0) {
        values = calloc(spec_count, sizeof(*values));
        if (values == NULL) {
            return ENOMEM;
        }
        for (size_t i = 0; i < spec_count; i++) {
            values[i].name = specs[i].name;
        }
    }
    if (argc > 1) {
        positionals = calloc((size_t)argc, sizeof(*positionals));
        if (positionals == NULL) {
            release_arrays(values, spec_count, NULL);
            return ENOMEM;
        }
    }

    int rc = 0;
    int end_of_options = 0;

    for (int i = 1; i < argc && rc == 0; i++) {
        const char *token = argv[i];

        if (token == NULL) {
            rc = EINVAL;
            break;
        }
        if (!end_of_options && strcmp(token, "--") == 0) {
            end_of_options = 1;
            continue;
        }

        if (!end_of_options && token[0] == '-' && token[1] == '-' &&
            token[2] != '\0') {
            const char *name = token + 2;
            const char *equals = strchr(name, '=');
            size_t name_len = equals != NULL ? (size_t)(equals - name)
                                             : strlen(name);
            const cli_option_spec *spec =
                find_long(specs, spec_count, name, name_len);
            if (spec == NULL) {
                rc = EINVAL;
                break;
            }
            if (spec->takes_value != 0) {
                const char *value = NULL;
                if (equals != NULL) {
                    value = equals + 1;
                    if (*value == '\0') {
                        rc = EINVAL;
                        break;
                    }
                } else {
                    if (i + 1 >= argc) {
                        rc = EINVAL;
                        break;
                    }
                    value = argv[++i];
                }
                rc = record_option(&values[spec_index(specs, spec)],
                                   spec, value);
            } else {
                if (equals != NULL) {
                    rc = EINVAL;
                    break;
                }
                rc = record_option(&values[spec_index(specs, spec)],
                                   spec, NULL);
            }
            continue;
        }

        if (!end_of_options && token[0] == '-' && token[1] != '\0' &&
            token[1] != '-') {
            if (token[2] != '\0') {
                /* No short-option bundling: deterministic and unambiguous. */
                rc = EINVAL;
                break;
            }
            const cli_option_spec *spec =
                find_short(specs, spec_count, token[1]);
            if (spec == NULL) {
                rc = EINVAL;
                break;
            }
            if (spec->takes_value != 0) {
                if (i + 1 >= argc) {
                    rc = EINVAL;
                    break;
                }
                const char *value = argv[++i];
                rc = record_option(&values[spec_index(specs, spec)],
                                   spec, value);
            } else {
                rc = record_option(&values[spec_index(specs, spec)],
                                   spec, NULL);
            }
            continue;
        }

        positionals[positional_count++] = token;
    }

    if (rc != 0) {
        release_arrays(values, spec_count, positionals);
        return rc;
    }

    out->specs = specs;
    out->spec_count = spec_count;
    out->values = values;
    out->positionals = positionals;
    out->positional_count = positional_count;
    out->argv0 = argc > 0 ? argv[0] : NULL;
    return 0;
}

void cli_args_free(cli_args *args) {
    if (args == NULL) {
        return;
    }
    release_arrays(args->values, args->spec_count, args->positionals);
    args_clear(args);
}

const cli_option_value *cli_args_get(const cli_args *args, const char *name) {
    if (args == NULL || args->specs == NULL || name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < args->spec_count; i++) {
        if (strcmp(args->specs[i].name, name) == 0) {
            return &args->values[i];
        }
    }
    return NULL;
}

int cli_args_flag(const cli_args *args, const char *name) {
    const cli_option_value *entry = cli_args_get(args, name);

    return entry != NULL && entry->present != 0;
}

const char *cli_args_value(const cli_args *args, const char *name) {
    const cli_option_value *entry = cli_args_get(args, name);

    return entry != NULL ? entry->value : NULL;
}

/* ------------------------------------------------------------------------- */
/* Global flags                                                              */
/* ------------------------------------------------------------------------- */

static int push_verb_arg(char ***args, size_t *count, size_t *capacity,
                         char *token) {
    if (*count == *capacity) {
        size_t grown_capacity = *capacity == 0 ? 8 : *capacity * 2;
        char **grown = realloc(*args, grown_capacity * sizeof(**args));
        if (grown == NULL) {
            return ENOMEM;
        }
        *args = grown;
        *capacity = grown_capacity;
    }
    (*args)[(*count)++] = token;
    return 0;
}

/* Global value extraction result: matched / not this option / error. */
enum { GLOBAL_MATCH = 0, GLOBAL_NOMATCH = 1 };

/*
 * Extract a global option value from `--name=value` or `--name value`.
 * Advances *index when the separate-token form is used.
 */
static int global_value(char **argv, int argc, int *index, const char *token,
                        const char *name, const char **value_out) {
    size_t name_len = strlen(name);
    const char *body = token + 2;

    if (strncmp(body, name, name_len) == 0 && body[name_len] == '=') {
        const char *value = body + name_len + 1;
        if (*value == '\0') {
            return EINVAL;
        }
        *value_out = value;
        return GLOBAL_MATCH;
    }
    if (strcmp(body, name) == 0) {
        if (*index + 1 >= argc) {
            return EINVAL;
        }
        *value_out = argv[++(*index)];
        if (**value_out == '\0') {
            return EINVAL;
        }
        return GLOBAL_MATCH;
    }
    return GLOBAL_NOMATCH;
}

static int parse_timeout(const char *text, int *out) {
    char *end = NULL;
    long value;

    if (text == NULL || *text == '\0') {
        return EINVAL;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 ||
        value > INT_MAX) {
        return EINVAL;
    }
    *out = (int)value;
    return 0;
}

int cli_globals_parse(int argc, char **argv, cli_globals *out) {
    if (out == NULL) {
        return EINVAL;
    }
    memset(out, 0, sizeof(*out));
    out->lock_timeout = -1;
    if (argc < 0 || (argc > 0 && argv == NULL)) {
        return EINVAL;
    }
    if (argc == 0) {
        return 0;
    }

    char **verb_args = NULL;
    size_t verb_arg_count = 0;
    size_t verb_arg_capacity = 0;
    int verb_seen = 0;
    int end_of_options = 0;
    int rc = 0;

    for (int i = 1; i < argc && rc == 0; i++) {
        char *token = argv[i];

        if (token == NULL) {
            rc = EINVAL;
            break;
        }
        if (!end_of_options && strcmp(token, "--") == 0) {
            end_of_options = 1;
            continue;
        }

        if (!end_of_options && token[0] == '-' && token[1] == '-' &&
            token[2] != '\0') {
            const char *value = NULL;

            if (strcmp(token, "--help") == 0) {
                out->help = 1;
                continue;
            }
            if (strcmp(token, "--version") == 0) {
                out->version = 1;
                continue;
            }
            if (strcmp(token, "--json") == 0) {
                out->json = 1;
                continue;
            }
            if (strcmp(token, "--yes") == 0) {
                out->yes = 1;
                continue;
            }
            if (strcmp(token, "--dry-run") == 0) {
                out->dry_run = 1;
                continue;
            }
            int matched =
                global_value(argv, argc, &i, token, "region", &value);
            if (matched == GLOBAL_MATCH) {
                if (out->region_explicit != 0) {
                    rc = EINVAL;
                    break;
                }
                out->region = value;
                out->region_explicit = 1;
                continue;
            }
            if (matched != GLOBAL_NOMATCH) {
                rc = matched;
                break;
            }
            matched = global_value(argv, argc, &i, token, "project", &value);
            if (matched == GLOBAL_MATCH) {
                if (out->project != NULL) {
                    rc = EINVAL;
                    break;
                }
                out->project = value;
                continue;
            }
            if (matched != GLOBAL_NOMATCH) {
                rc = matched;
                break;
            }
            matched =
                global_value(argv, argc, &i, token, "lock-timeout", &value);
            if (matched == GLOBAL_MATCH) {
                int timeout = 0;
                if (out->lock_timeout != -1) {
                    rc = EINVAL;
                    break;
                }
                rc = parse_timeout(value, &timeout);
                if (rc != 0) {
                    break;
                }
                out->lock_timeout = timeout;
                continue;
            }
            if (matched != GLOBAL_NOMATCH) {
                rc = matched;
                break;
            }
            if (verb_seen == 0) {
                rc = EINVAL; /* unknown global before the verb */
                break;
            }
            rc = push_verb_arg(&verb_args, &verb_arg_count, &verb_arg_capacity,
                               token);
            continue;
        }

        if (!end_of_options && token[0] == '-' && token[1] != '\0' &&
            token[1] != '-') {
            if (strcmp(token, "-h") == 0) {
                out->help = 1;
                continue;
            }
            if (strcmp(token, "-y") == 0) {
                out->yes = 1;
                continue;
            }
            if (verb_seen == 0) {
                rc = EINVAL; /* unknown short global before the verb */
                break;
            }
            rc = push_verb_arg(&verb_args, &verb_arg_count, &verb_arg_capacity,
                               token);
            continue;
        }

        if (verb_seen == 0) {
            out->verb = token;
            verb_seen = 1;
        } else {
            rc = push_verb_arg(&verb_args, &verb_arg_count, &verb_arg_capacity,
                               token);
        }
    }

    if (rc == 0 && verb_seen != 0) {
        char **vector = calloc(verb_arg_count + 1, sizeof(*vector));
        if (vector == NULL) {
            rc = ENOMEM;
        } else {
            vector[0] = (char *)out->verb;
            for (size_t i = 0; i < verb_arg_count; i++) {
                vector[i + 1] = verb_args[i];
            }
            free(verb_args);
            verb_args = NULL;
            out->verb_argv = vector;
            out->verb_argc = (int)(verb_arg_count + 1);
        }
    }

    free(verb_args);
    if (rc != 0) {
        free(out->verb_argv);
        memset(out, 0, sizeof(*out));
        out->lock_timeout = -1;
        return rc;
    }
    out->program = argv[0];
    return 0;
}

void cli_globals_free(cli_globals *globals) {
    if (globals == NULL) {
        return;
    }
    free(globals->verb_argv);
    memset(globals, 0, sizeof(*globals));
    globals->lock_timeout = -1;
}
