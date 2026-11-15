/* Smoke test for the vendored yyjson 0.13.0 library: parse a small object,
 * read a string and an integer back, then serialize and re-parse it. */

#include <stdlib.h>
#include <string.h>

#include "yyjson.h"

int main(void) {
    const char *json = "{\"status\":\"ok\",\"count\":3}";

    yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
    if (doc == NULL) {
        return 1;
    }

    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return 2;
    }

    yyjson_val *status = yyjson_obj_get(root, "status");
    yyjson_val *count = yyjson_obj_get(root, "count");
    if (!yyjson_is_str(status) || strcmp(yyjson_get_str(status), "ok") != 0) {
        yyjson_doc_free(doc);
        return 3;
    }
    if (!yyjson_is_int(count) || yyjson_get_int(count) != 3) {
        yyjson_doc_free(doc);
        return 4;
    }

    yyjson_mut_doc *mut = yyjson_mut_doc_new(NULL);
    if (mut == NULL) {
        yyjson_doc_free(doc);
        return 5;
    }
    yyjson_mut_val *obj = yyjson_mut_obj(mut);
    yyjson_mut_doc_set_root(mut, obj);
    yyjson_mut_obj_add_str(mut, obj, "status", "ok");
    yyjson_mut_obj_add_int(mut, obj, "count", 3);

    char *out = yyjson_mut_write(mut, 0, NULL);
    if (out == NULL) {
        yyjson_mut_doc_free(mut);
        yyjson_doc_free(doc);
        return 6;
    }

    yyjson_doc *doc2 = yyjson_read(out, strlen(out), 0);
    free(out);
    yyjson_mut_doc_free(mut);
    yyjson_doc_free(doc);

    if (doc2 == NULL) {
        return 7;
    }
    yyjson_doc_free(doc2);
    return 0;
}
