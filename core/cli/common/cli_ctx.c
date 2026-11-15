/*
 * cli_ctx.c — context construction, verb registration and signal policy.
 *
 * cli_ctx_init() is the single place that turns a raw command line into the
 * frozen context the wave-4 verbs and wave-5 dispatcher consume: parsed
 * globals, validated config, opened state store and (for mutating verbs) the
 * coarse per-project/per-region flock. `status` is deliberately lockless.
 */

#include "cli.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* Context                                                                   */
/* ------------------------------------------------------------------------- */

struct cli_ctx {
    cli_globals globals;
    stackctl_config *config;
    state_store *state;
    int lock_held;
};

static const char *const verb_names[] = {
    "provision", "deploy", "refresh-ami", "launch",
    "terminate", "status", "start",       "stop",
};

int cli_ctx_init(int argc, char **argv, cli_ctx **out) {
    cli_globals globals;
    cli_ctx *ctx;
    int rc;

    if (out == NULL) {
        return EINVAL;
    }
    *out = NULL;

    rc = cli_globals_parse(argc, argv, &globals);
    if (rc != 0) {
        cli_err("stackctl: invalid command line\n");
        return rc;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        cli_globals_free(&globals);
        return ENOMEM;
    }
    ctx->globals = globals; /* transfer ownership */

    if (ctx->globals.help != 0 || ctx->globals.version != 0) {
        cli_signal_install();
        *out = ctx;
        return 0;
    }
    if (ctx->globals.verb == NULL) {
        cli_err("stackctl: missing verb\n");
        cli_ctx_free(ctx);
        return EINVAL;
    }
    if (ctx->globals.project == NULL) {
        cli_err("stackctl: missing required --project <config-dir>\n");
        cli_ctx_free(ctx);
        return EINVAL;
    }

    rc = config_load(ctx->globals.project, ctx->globals.region_explicit,
                     ctx->globals.region, &ctx->config);
    if (rc != 0) {
        cli_err("stackctl: invalid configuration\n");
        cli_ctx_free(ctx);
        return rc;
    }

    rc = state_open(config_project(ctx->config), config_region(ctx->config),
                    &ctx->state);
    if (rc != 0) {
        cli_err("stackctl: cannot open state store\n");
        cli_ctx_free(ctx);
        return rc;
    }

    if (cli_verb_mutates(ctx->globals.verb) != 0) {
        rc = state_lock(config_project(ctx->config), config_region(ctx->config),
                        ctx->globals.lock_timeout);
        if (rc != 0) {
            if (rc == ETIMEDOUT) {
                cli_err("stackctl: timed out waiting for the project lock\n");
            } else {
                cli_err("stackctl: cannot acquire the project lock\n");
            }
            cli_ctx_free(ctx);
            return rc;
        }
        ctx->lock_held = 1;
    }

    cli_signal_install();
    *out = ctx;
    return 0;
}

void cli_ctx_free(cli_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->lock_held != 0) {
        (void)state_unlock();
    }
    state_close(ctx->state);
    config_free(ctx->config);
    cli_globals_free(&ctx->globals);
    free(ctx);
}

const char *cli_ctx_program(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.program : NULL;
}

const char *cli_ctx_verb(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.verb : NULL;
}

const stackctl_config *cli_ctx_config(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->config : NULL;
}

state_store *cli_ctx_state(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->state : NULL;
}

int cli_ctx_json(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.json : 0;
}

int cli_ctx_yes(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.yes : 0;
}

int cli_ctx_dry_run(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.dry_run : 0;
}

int cli_ctx_lock_timeout(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.lock_timeout : -1;
}

int cli_ctx_verb_argc(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.verb_argc : 0;
}

char **cli_ctx_verb_argv(const cli_ctx *ctx) {
    return ctx != NULL ? ctx->globals.verb_argv : NULL;
}

int cli_ctx_parse_args(const cli_ctx *ctx, const cli_option_spec *specs,
                       size_t spec_count, cli_args *out) {
    if (ctx == NULL) {
        return EINVAL;
    }
    return cli_args_parse(cli_ctx_verb_argc(ctx), cli_ctx_verb_argv(ctx), specs,
                          spec_count, out);
}

/* ------------------------------------------------------------------------- */
/* Verb registration                                                         */
/* ------------------------------------------------------------------------- */

const cli_command *cli_command_find(const cli_command *commands, size_t count,
                                    const char *name) {
    if (commands == NULL || name == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        if (commands[i].name != NULL && strcmp(commands[i].name, name) == 0) {
            return &commands[i];
        }
    }
    return NULL;
}

int cli_verb_known(const char *verb) {
    if (verb == NULL) {
        return 0;
    }
    for (size_t i = 0; i < sizeof(verb_names) / sizeof(verb_names[0]); i++) {
        if (strcmp(verb_names[i], verb) == 0) {
            return 1;
        }
    }
    return 0;
}

int cli_verb_mutates(const char *verb) {
    return cli_verb_known(verb) != 0 && strcmp(verb, "status") != 0;
}

const char *const *cli_verb_names(size_t *count) {
    if (count != NULL) {
        *count = sizeof(verb_names) / sizeof(verb_names[0]);
    }
    return verb_names;
}

/* ------------------------------------------------------------------------- */
/* Signals                                                                   */
/* ------------------------------------------------------------------------- */

static volatile sig_atomic_t signal_count;
static volatile sig_atomic_t signal_seen;
static volatile sig_atomic_t signal_consumed;

static void on_signal(int number) {
    signal_count++;
    if (signal_count >= 2) {
        _exit(128 + number); /* second signal: immediate death, no cleanup */
    }
    if (signal_seen == 0) {
        signal_seen = number;
    }
}

void cli_signal_install(void) {
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
}

int cli_signal_received(void) { return signal_count != 0; }

int cli_signal_number(void) { return (int)signal_seen; }

void cli_signal_mark_consumed(void) { signal_consumed = 1; }

int cli_signal_consumed(void) { return signal_consumed != 0; }

int cli_abort_check(void *user) {
    (void)user;
    return cli_signal_received();
}

void cli_signal_test_fire(int number) {
    if (signal_seen == 0) {
        signal_seen = number;
    }
    signal_count++;
}

void cli_signal_test_reset(void) {
    signal_count = 0;
    signal_seen = 0;
    signal_consumed = 0;
}
