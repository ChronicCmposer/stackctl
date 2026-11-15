/*
 * ini.h — `~/.aws/credentials` upsert (spec §2 ini module).
 *
 * Port of the family's `upsert_ini_section`: update one key inside one INI
 * section while preserving every unrelated section, comment and line, taking a
 * timestamped backup of the previous file and replacing the target atomically
 * (same-directory temp file + rename(2)). All public symbols are prefixed
 * `ini_`; the module is pure C with no network dependencies.
 *
 * Error model (CONTRACT.md): returns 0 on success, else a non-zero errno-style
 * code. Diagnostics go to stderr only.
 */

#ifndef STACKCTL_INI_H
#define STACKCTL_INI_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Upsert `key = secret` in `[section]` of the INI file at `path`.
 *
 *   path             target INI file. Updated in place atomically; its real
 *                    directory hosts the temporary file.
 *   section          section name without brackets.
 *   key              key to create or update inside the section.
 *   secret           value written verbatim after `key = `.
 *   backup_path_out  optional; on success receives a heap-allocated path to
 *                    the timestamped backup of the previous file, or NULL when
 *                    the file did not exist yet. Free with free().
 *
 * Existing sections (including `[default]`) and unknown lines are preserved
 * byte-for-byte except for the single target key line. A missing section is
 * appended. The file and its backup are created 0600 (credentials hygiene).
 *
 * Returns 0 on success, EINVAL on bad arguments, or another errno-style code
 * on I/O failure.
 */
int ini_upsert_section(const char *path, const char *section, const char *key,
                       const char *secret, char **backup_path_out);

#ifdef __cplusplus
}
#endif

#endif /* STACKCTL_INI_H */
