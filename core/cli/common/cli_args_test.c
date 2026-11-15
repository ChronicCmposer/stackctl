/*
 * cli_args_test.c — deterministic argv parsing and global-flag tests.
 *
 * Exercises the frozen cli.h parsing surface: `--flag=value` and `--flag
 * value`, repeated flags, required/optional values, duplicate/unknown flags,
 * empty values, `--` end-of-options, positionals, and global-flag extraction
 * from a full command line.
 */

#include "cli.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))

static const cli_option_spec specs[] = {
    {"project", 'p', 1, 0, "<dir>", "project config directory"},
    {"region", 'r', 1, 0, "<name>", "region variant"},
    {"json", 'j', 0, 0, NULL, "JSON output"},
    {"yes", 'y', 0, 0, NULL, "assume yes"},
    {"tag", 't', 1, 1, "<tag>", "release tag (repeatable)"},
};

static int parse(char **argv, cli_args *args) {
    int argc = 0;

    while (argv[argc] != NULL) {
        argc++;
    }
    return cli_args_parse(argc, argv, specs, ARRAY_LEN(specs), args);
}

static void test_basic_forms(void) {
    char *argv[] = {"provision", "--project=/srv/cfg",
                    "--region",  "eu-west-1", "--json",
                    "--tag=a",   "--tag",     "b",
                    "--tag",     "c",         "pos1",
                    "pos2",      NULL};
    cli_args args = {0};

    CHECK(parse(argv, &args) == 0, "parse succeeds");
    CHECK(strcmp(cli_args_value(&args, "project"), "/srv/cfg") == 0,
          "--flag=value form");
    CHECK(strcmp(cli_args_value(&args, "region"), "eu-west-1") == 0,
          "--flag value form");
    CHECK(cli_args_flag(&args, "json") == 1, "boolean flag present");
    CHECK(cli_args_flag(&args, "yes") == 0, "absent boolean flag");
    const cli_option_value *tag = cli_args_get(&args, "tag");
    CHECK(tag != NULL, "repeatable entry found");
    CHECK(tag != NULL && tag->count == 3, "repeatable count");
    CHECK(tag != NULL && tag->value_count == 3, "repeatable value count");
    CHECK(tag != NULL && strcmp(tag->values[0], "a") == 0, "repeatable first");
    CHECK(tag != NULL && strcmp(tag->values[2], "c") == 0, "repeatable last");
    CHECK(tag != NULL && strcmp(tag->value, "c") == 0, "repeatable last value");
    CHECK(args.positional_count == 2, "positional count");
    CHECK(strcmp(args.positionals[0], "pos1") == 0, "positional order");
    CHECK(strcmp(args.positionals[1], "pos2") == 0, "positional order 2");
    cli_args_free(&args);
    CHECK(args.values == NULL && args.positionals == NULL, "free zeroes");
    cli_args_free(&args); /* idempotent */
}

static void test_short_flags(void) {
    char *argv[] = {"status", "-j", "-y", "-p", "cfg", NULL};
    cli_args args = {0};

    CHECK(parse(argv, &args) == 0, "short flags parse");
    CHECK(cli_args_flag(&args, "json") == 1, "-j");
    CHECK(cli_args_flag(&args, "yes") == 1, "-y");
    CHECK(strcmp(cli_args_value(&args, "project"), "cfg") == 0, "-p value");
    cli_args_free(&args);
}

static void test_errors(void) {
    {
        char *argv[] = {"verb", "--project", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == EINVAL, "missing value is EINVAL");
        CHECK(args.values == NULL, "failure leaves no result");
    }
    {
        char *argv[] = {"verb", "--project=", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == EINVAL, "empty --flag= is EINVAL");
    }
    {
        char *argv[] = {"verb", "--bogus", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == EINVAL, "unknown long flag is EINVAL");
    }
    {
        char *argv[] = {"verb", "-z", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == EINVAL, "unknown short flag is EINVAL");
    }
    {
        char *argv[] = {"verb", "--project", "a", "--project", "b", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == EINVAL,
              "duplicate non-repeatable value is EINVAL");
    }
    {
        char *argv[] = {"verb", "--json=1", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == EINVAL, "boolean with =value is EINVAL");
    }
}

static void test_boolean_duplicate_and_terminator(void) {
    {
        char *argv[] = {"verb", "--json", "--json", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == 0, "duplicate boolean accepted");
        const cli_option_value *entry = cli_args_get(&args, "json");
        CHECK(entry != NULL && entry->count == 2, "duplicate boolean count");
        cli_args_free(&args);
    }
    {
        char *argv[] = {"verb", "--", "--json", "-x", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == 0, "-- ends option parsing");
        CHECK(cli_args_flag(&args, "json") == 0, "flag after -- is positional");
        CHECK(args.positional_count == 2, "both post--- tokens positional");
        CHECK(strcmp(args.positionals[0], "--json") == 0, "positional literal");
    }
    {
        char *argv[] = {"verb", "-", NULL};
        cli_args args = {0};
        CHECK(parse(argv, &args) == 0, "lone dash is positional");
        CHECK(args.positional_count == 1 &&
                  strcmp(args.positionals[0], "-") == 0,
              "lone dash kept");
    }
}

static void test_bad_inputs(void) {
    cli_args args = {0};
    char *argv[] = {"verb", NULL};

    CHECK(cli_args_parse(1, argv, NULL, 1, &args) == EINVAL,
          "NULL spec table with specs is EINVAL");
    CHECK(cli_args_parse(1, argv, specs, ARRAY_LEN(specs), NULL) == EINVAL,
          "NULL out is EINVAL");
    CHECK(cli_args_get(NULL, "json") == NULL, "NULL args get");
    CHECK(cli_args_get(&args, NULL) == NULL, "NULL name get");
    CHECK(cli_args_flag(NULL, "json") == 0, "NULL args flag");
    CHECK(cli_args_value(NULL, "json") == NULL, "NULL args value");
    CHECK(cli_args_value(&args, "json") == NULL, "absent value");
}

/* ------------------------------------------------------------------------- */
/* Global flags                                                              */
/* ------------------------------------------------------------------------- */

static void test_globals_full(void) {
    char *argv[] = {"stackctl", "--region", "eu-west-1", "--project", "./cfg",
                    "provision", "--rotate", "--json", "--yes", NULL};
    cli_globals globals = {0};

    CHECK(cli_globals_parse(9, argv, &globals) == 0, "globals parse");
    CHECK(strcmp(globals.program, "stackctl") == 0, "program");
    CHECK(strcmp(globals.verb, "provision") == 0, "verb");
    CHECK(globals.region_explicit == 1, "region explicit");
    CHECK(strcmp(globals.region, "eu-west-1") == 0, "region value");
    CHECK(strcmp(globals.project, "./cfg") == 0, "project value");
    CHECK(globals.json == 1, "globals may follow the verb");
    CHECK(globals.yes == 1, "yes after verb");
    CHECK(globals.dry_run == 0, "dry-run default");
    CHECK(globals.lock_timeout == -1, "lock timeout default forever");
    CHECK(globals.verb_argc == 2, "verb args exclude globals");
    CHECK(strcmp(globals.verb_argv[0], "provision") == 0, "verb argv[0]");
    CHECK(strcmp(globals.verb_argv[1], "--rotate") == 0, "verb argv[1]");
    cli_globals_free(&globals);
    CHECK(globals.verb_argv == NULL, "free zeroes verb argv");
    cli_globals_free(&globals); /* idempotent */
}

static void test_globals_after_verb(void) {
    char *argv[] = {"stackctl", "status", "--json", NULL};
    cli_globals globals = {0};

    CHECK(cli_globals_parse(3, argv, &globals) == 0, "parse status --json");
    CHECK(strcmp(globals.verb, "status") == 0, "status verb");
    CHECK(globals.json == 1, "trailing --json is global");
    CHECK(globals.verb_argc == 1, "only the verb remains");
    cli_globals_free(&globals);
}

static void test_globals_values(void) {
    {
        char *argv[] = {"stackctl", "--dry-run", "--lock-timeout", "5",
                        "--project=cfg", "deploy", "--tag", "v1", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(8, argv, &globals) == 0, "parse deploy");
        CHECK(globals.dry_run == 1, "dry-run");
        CHECK(globals.lock_timeout == 5, "lock timeout parsed");
        CHECK(strcmp(globals.project, "cfg") == 0, "project= form");
        CHECK(globals.verb_argc == 3, "verb args");
        CHECK(strcmp(globals.verb_argv[1], "--tag") == 0, "unrelated flag kept");
        CHECK(strcmp(globals.verb_argv[2], "v1") == 0, "unrelated value kept");
        cli_globals_free(&globals);
    }
    {
        char *argv[] = {"stackctl", "--help", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(2, argv, &globals) == 0, "--help alone");
        CHECK(globals.help == 1, "help flag");
        CHECK(globals.verb == NULL, "help has no verb");
        cli_globals_free(&globals);
    }
    {
        char *argv[] = {"stackctl", "--version", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(2, argv, &globals) == 0, "--version alone");
        CHECK(globals.version == 1, "version flag");
        cli_globals_free(&globals);
    }
    {
        char *argv[] = {"stackctl", "--lock-timeout", "0", "status", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(4, argv, &globals) == 0, "zero timeout");
        CHECK(globals.lock_timeout == 0, "zero timeout value");
        cli_globals_free(&globals);
    }
}

static void test_globals_errors(void) {
    {
        char *argv[] = {"stackctl", "--bogus", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(2, argv, &globals) == EINVAL,
              "unknown global before verb");
    }
    {
        char *argv[] = {"stackctl", "--project", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(2, argv, &globals) == EINVAL,
              "missing global value");
    }
    {
        char *argv[] = {"stackctl", "--project=", "status", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(3, argv, &globals) == EINVAL,
              "empty global value");
    }
    {
        char *argv[] = {"stackctl", "--lock-timeout", "-1", "status", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(4, argv, &globals) == EINVAL,
              "negative lock timeout rejected");
    }
    {
        char *argv[] = {"stackctl", "--lock-timeout", "abc", "status", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(4, argv, &globals) == EINVAL,
              "non-numeric lock timeout rejected");
    }
    {
        char *argv[] = {"stackctl", "provision", "--bogus", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(3, argv, &globals) == 0,
              "unknown flag after verb is a verb arg");
        CHECK(globals.verb_argc == 2, "unknown flag preserved for the verb");
        cli_globals_free(&globals);
    }
    {
        char *argv[] = {"stackctl", "--", "provision", "--json", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(4, argv, &globals) == 0, "-- before verb");
        CHECK(strcmp(globals.verb, "provision") == 0, "verb after --");
        CHECK(globals.json == 0, "globals not parsed after --");
        CHECK(globals.verb_argc == 2, "post--- args kept");
        cli_globals_free(&globals);
    }
    {
        char *argv[] = {"stackctl", NULL};
        cli_globals globals = {0};
        CHECK(cli_globals_parse(1, argv, &globals) == 0, "empty argv parses");
        CHECK(globals.verb == NULL, "no verb");
        CHECK(globals.project == NULL, "no project");
        cli_globals_free(&globals);
    }
    {
        CHECK(cli_globals_parse(0, NULL, NULL) == EINVAL, "NULL out");
    }
}

int main(void) {
    test_basic_forms();
    test_short_flags();
    test_errors();
    test_boolean_duplicate_and_terminator();
    test_bad_inputs();
    test_globals_full();
    test_globals_after_verb();
    test_globals_values();
    test_globals_errors();

    if (failures != 0) {
        fprintf(stderr, "cli_args_test: %d check(s) failed\n", failures);
        return 1;
    }
    printf("cli_args_test: all checks passed\n");
    return 0;
}
