#include "template_check.h"

#include <stdio.h>
#include <string.h>

static tc_mode parse_mode(const char *text) {
    return strcmp(text, "infra") == 0 ? TC_MODE_INFRA : TC_MODE_OPERATOR;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: template_check <operator|infra> FILE...\n");
        return 2;
    }
    tc_mode mode = parse_mode(argv[1]);
    int status = 0;
    for (int i = 2; i < argc; i++) {
        int result = tc_check_file(argv[i], mode);
        if (result != 0) {
            status = result;
        }
    }
    return status;
}
