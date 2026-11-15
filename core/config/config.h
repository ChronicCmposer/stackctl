/*
 * config.h — stackctl project configuration (spec §3).
 *
 * Loads a flat KEY=VALUE `.env` (or `.env.<region>` variant) from a project's
 * `deploy/aws/` directory and validates it fail-closed. All public symbols are
 * prefixed `config_`; the module is pure C with no network dependencies.
 *
 * Error model (CONTRACT.md): every function returns 0 on success and a
 * non-zero errno-style code otherwise. Validation diagnostics are written to
 * stderr; out-params are untouched on failure.
 */

#ifndef STACKCTL_CONFIG_H
#define STACKCTL_CONFIG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque parsed+validated configuration. */
typedef struct stackctl_config stackctl_config;

/*
 * One validated `INGRESS_TCP` / `INGRESS_UDP` entry (CONTRACT C3).
 *
 * `port` is 1..65535; `cidr` is a canonical NUL-terminated IPv4 CIDR such as
 * "0.0.0.0/0" (an omitted CIDR defaults to that value). Parsing and validation
 * happen at config load, so downstream code consumes trusted rules.
 */
typedef struct config_ingress_rule {
    unsigned port;
    char cidr[19];
} config_ingress_rule;

/* Maximum rules per protocol; the infra template has 8 indexed slots. */
#define CONFIG_INGRESS_MAX 8

/*
 * Load and validate the project configuration.
 *
 *   dir             `--project` config directory (may be relative; resolved
 *                   against $BUILD_WORKING_DIRECTORY when set, else cwd).
 *   region_explicit non-zero when `--region` was given on the command line.
 *   region_flag     region name for an explicit `--region`; ignored when
 *                   region_explicit is zero.
 *   out             receives a heap-allocated config on success.
 *
 * File selection: explicit region loads `<dir>/.env.<region>` (hard error if
 * absent) and requires it to declare `REGION=<region>` exactly; otherwise
 * `<dir>/.env` is loaded and a region for which a `.env.<region>` sibling
 * exists is rejected. Unknown keys, missing required keys per declared
 * arch/module, cross-key inconsistencies, a PROJECT that fails
 * `^[a-z][a-z0-9]+$`, or a PROJECT longer than the per-region S3 bucket-name
 * budget are all errors. The repo root is resolved by walking up to the first
 * ancestor containing MODULE.bazel; a config file whose real path escapes that
 * root is an error.
 *
 * Returns 0 on success, else EINVAL (validation), ENOENT (missing file or
 * repo root), or another errno-style code. Frees nothing on failure.
 */
int config_load(const char *dir, int region_explicit, const char *region_flag,
                stackctl_config **out);

/* Release a config returned by config_load(). Safe on NULL. */
void config_free(stackctl_config *cfg);

/*
 * Typed getters. config_get() returns the configured value or NULL when the
 * key is unset; optional keys with documented defaults return their default
 * (ROOT_VOLUME_TYPE=gp3, SSH_USER=ec2-user, ENABLE_SPOT_ALERTS=false,
 * DDNS_ONBOX=false, IP_ECHO_URL=https://checkip.amazonaws.com,
 * BAZEL_COMMAND=bazel, SETUP_ENTRYPOINT=deploy.sh, SSH_PORT=22). REGION,
 * PROJECT and ARCH return the validated values.
 */
const char *config_get(const stackctl_config *cfg, const char *key);
const char *config_region(const stackctl_config *cfg);
const char *config_project(const stackctl_config *cfg);

/*
 * Architecture list derived from ARCH: {"amd64", NULL}, {"arm64", NULL}, or
 * {"amd64", "arm64", NULL}. The returned array and its strings are owned by
 * cfg and remain valid until config_free().
 */
const char *const *config_arch_list(const stackctl_config *cfg);

/*
 * Optional wave-2 keys (CONTRACT C3): the ImageBuilder parent image (valid
 * only with ENABLE_IMAGE_BUILDER=true) and the IAM permissions boundary ARN.
 * Each returns NULL when the key is unset; the string is owned by cfg.
 */
const char *config_image_builder_parent_image(const stackctl_config *cfg);
const char *config_permissions_boundary_arn(const stackctl_config *cfg);

/*
 * Parsed ingress rules (CONTRACT C3). Each getter returns the rule count and,
 * when `rules_out` is non-NULL, points it at the cfg-owned array (NULL when the
 * count is zero). The array is valid until config_free().
 */
size_t config_ingress_tcp(const stackctl_config *cfg,
                          const config_ingress_rule **rules_out);
size_t config_ingress_udp(const stackctl_config *cfg,
                          const config_ingress_rule **rules_out);

/*
 * The real path of the config directory this config was loaded from. Every
 * verb that needs project-relative files (`.env`, `.env.example`, sibling
 * region variants) must use this rather than re-deriving `$PWD/deploy/aws`, so
 * an explicit `--project` elsewhere is honoured. The string is owned by cfg
 * and remains valid until config_free(); NULL when cfg is NULL.
 */
const char *config_dir(const stackctl_config *cfg);

/*
 * Resolve the repo root for a config directory: realpath(config_dir) then walk
 * up to the first ancestor containing a regular `MODULE.bazel`. On success
 * *root_out receives a heap-allocated absolute path (free with free());
 * returns 0, else EINVAL/ENOENT/ENOMEM.
 */
int config_repo_root(const char *config_dir, char **root_out);

/*
 * Return $BUILD_WORKING_DIRECTORY when set and non-empty, else NULL. This is
 * the base for resolving a relative --project under `bazel run`.
 */
const char *config_build_working_directory(void);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_CONFIG_H */
