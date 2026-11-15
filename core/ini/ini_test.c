/*
 * ini_test.c — upsert semantics for core/ini (spec §2 ini module).
 *
 * Covers: section preservation, key update idempotence, section scoping,
 * timestamped backup contents, 0600 permissions, atomic temp cleanup, and
 * creation of a missing file. No external test framework: exit non-zero on any
 * failed check.
 */

#include "ini.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, label);   \
            failures++;                                                        \
        }                                                                      \
    } while (0)

static char *make_temp_root(void) {
    char template[] = "/tmp/stackctl-ini-XXXXXX";
    char *root = mkdtemp(template);

    if (root == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    return strdup(root);
}

static char *join_path(const char *dir, const char *name) {
    size_t need = strlen(dir) + strlen(name) + 2;
    char *path = malloc(need);

    if (path == NULL) {
        perror("malloc");
        exit(1);
    }
    snprintf(path, need, "%s/%s", dir, name);
    return path;
}

static void write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t len = strlen(content);

    if (fd < 0 || write(fd, content, len) != (ssize_t)len) {
        perror("write_file");
        exit(1);
    }
    close(fd);
}

static char *read_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    char *buffer;
    long size;

    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buffer = malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, fp) != (size_t)size) {
        free(buffer);
        fclose(fp);
        return NULL;
    }
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

static size_t count_substring(const char *haystack, const char *needle) {
    size_t count = 0;
    size_t len = strlen(needle);
    const char *cursor = haystack;

    while ((cursor = strstr(cursor, needle)) != NULL) {
        count++;
        cursor += len;
    }
    return count;
}

static int file_mode(const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        return -1;
    }
    return (int)(st.st_mode & 0777);
}

static int has_atomic_temp_left(const char *dir) {
    DIR *handle = opendir(dir);
    struct dirent *entry;
    int leftovers = 0;

    if (handle == NULL) {
        return 1;
    }
    while ((entry = readdir(handle)) != NULL) {
        if (strncmp(entry->d_name, ".ini.tmp.", 9) == 0) {
            leftovers = 1;
        }
    }
    closedir(handle);
    return leftovers;
}

int main(void) {
    char *root = make_temp_root();
    char *path = join_path(root, "credentials");
    char *missing = join_path(root, "new-credentials");
    const char *initial =
        "[default]\n"
        "aws_access_key_id = OLDKEY\n"
        "aws_secret_access_key = OLDSECRET\n"
        "\n"
        "# keep this comment\n"
        "[other]\n"
        "region = eu-west-1\n"
        "aws_access_key_id = OTHERKEY\n";
    char *backup = NULL;
    char *content;

    write_file(path, initial);

    /* New section, timestamped backup, unrelated sections preserved. */
    CHECK(ini_upsert_section(path, "demo", "aws_access_key_id", "NEWKEY",
                             &backup) == 0,
          "upsert new section returns 0");
    CHECK(backup != NULL, "backup path returned for existing file");
    if (backup != NULL) {
        content = read_file(backup);
        CHECK(content != NULL && strcmp(content, initial) == 0,
              "backup holds the previous file byte-for-byte");
        CHECK(file_mode(backup) == 0600, "backup is mode 0600");
        free(content);
    }
    content = read_file(path);
    CHECK(content != NULL, "target readable");
    if (content != NULL) {
        CHECK(strstr(content, "aws_access_key_id = OLDKEY") != NULL,
              "default section key preserved");
        CHECK(strstr(content, "# keep this comment") != NULL,
              "comment preserved");
        CHECK(strstr(content, "[other]\nregion = eu-west-1\n") != NULL,
              "unrelated section preserved");
        CHECK(strstr(content, "aws_access_key_id = OTHERKEY") != NULL,
              "same-named key in another section preserved");
        CHECK(strstr(content, "[demo]\naws_access_key_id = NEWKEY\n") != NULL,
              "new section appended");
        CHECK(file_mode(path) == 0600, "target is mode 0600");
        free(content);
    }
    free(backup);
    backup = NULL;

    /* Update an existing key in the existing section: one section, one line. */
    CHECK(ini_upsert_section(path, "demo", "aws_access_key_id", "NEWKEY2",
                             NULL) == 0,
          "update existing key returns 0");
    CHECK(ini_upsert_section(path, "demo", "aws_secret_access_key", "DEMOSECRET",
                             NULL) == 0,
          "add second key to existing section");
    content = read_file(path);
    CHECK(content != NULL, "target readable after update");
    if (content != NULL) {
        CHECK(count_substring(content, "[demo]") == 1,
              "existing section not duplicated");
        CHECK(count_substring(content, "aws_access_key_id = NEWKEY2") == 1,
              "existing key updated in place");
        CHECK(strstr(content, "= NEWKEY\n") == NULL,
              "old value no longer present");
        CHECK(strstr(content, "aws_secret_access_key = DEMOSECRET") != NULL,
              "second key written");
        CHECK(strstr(content, "aws_access_key_id = OLDKEY") != NULL,
              "default section still untouched");
        free(content);
    }
    CHECK(has_atomic_temp_left(root) == 0, "no atomic temp file left behind");

    /* Missing file: create it, no backup. */
    backup = (char *)0x1;
    CHECK(ini_upsert_section(missing, "demo", "aws_access_key_id", "FIRST",
                             &backup) == 0,
          "create missing file returns 0");
    CHECK(backup == NULL, "no backup for a previously absent file");
    content = read_file(missing);
    CHECK(content != NULL, "created file readable");
    if (content != NULL) {
        CHECK(strcmp(content, "[demo]\naws_access_key_id = FIRST\n") == 0,
              "created file has the requested section/key");
        free(content);
    }
    CHECK(file_mode(missing) == 0600, "created file is mode 0600");

    /* Defensive arguments. */
    CHECK(ini_upsert_section(NULL, "demo", "k", "v", NULL) == EINVAL,
          "NULL path rejected");
    CHECK(ini_upsert_section(path, NULL, "k", "v", NULL) == EINVAL,
          "NULL section rejected");
    CHECK(ini_upsert_section(path, "demo", NULL, "v", NULL) == EINVAL,
          "NULL key rejected");
    CHECK(ini_upsert_section(path, "demo", "k", NULL, NULL) == EINVAL,
          "NULL secret rejected");

    free(missing);
    free(path);
    free(root);
    if (failures != 0) {
        fprintf(stderr, "ini_test: %d failure(s)\n", failures);
        return 1;
    }
    return 0;
}
