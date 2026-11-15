/*
 * envfile.h — flat KEY=VALUE env-file parser (spec §3).
 *
 * Adapted from strimserver core/controller/c/envfile.c: comments, blank lines,
 * an optional `export ` prefix, and optional single/double quoting. There is
 * NO interpolation — values are literal. Unlike the reference parser this
 * returns an ordered key/value map instead of mutating the process env, and it
 * rejects duplicate keys (fail-closed config).
 */

#ifndef STACKCTL_ENVFILE_H
#define STACKCTL_ENVFILE_H

#include <stddef.h>

typedef struct config_envfile config_envfile;

/*
 * Parse `path` into a new envfile. Returns 0 on success; on failure returns
 * -1 and writes a description into err (when err_cap > 0). A malformed line,
 * an invalid key name, a duplicate key, or an over-long line are all errors.
 */
int config_envfile_load(const char *path, config_envfile **out, char *err,
                        size_t err_cap);

/* Return the value for key, or NULL when absent. */
const char *config_envfile_get(const config_envfile *ef, const char *key);

/* Ordered enumeration for unknown-key detection. */
size_t config_envfile_count(const config_envfile *ef);
const char *config_envfile_key_at(const config_envfile *ef, size_t index);
const char *config_envfile_value_at(const config_envfile *ef, size_t index);

void config_envfile_free(config_envfile *ef);

#endif /* STACKCTL_ENVFILE_H */
