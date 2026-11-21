/*
 * template_check — dependency-free structural validator for the canonical
 * stackctl CloudFormation templates (spec §6.1/§6.2/§6.3).
 *
 * The parser implements the conservative YAML subset the templates use:
 * block mappings, block sequences, scalars, CloudFormation short-form
 * intrinsic tags (treated as opaque scalars), quoted scalars and comments.
 * It deliberately rejects anything it cannot read structurally, because the
 * checker also gates TEMPLATE_OVERRIDE files fail-closed.
 */

#include "template_check.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ arena */

typedef struct arena_block {
    struct arena_block *next;
    size_t capacity;
    size_t used;
    unsigned char data[];
} arena_block;

typedef struct {
    arena_block *head;
} arena;

static void *arena_alloc(arena *a, size_t size) {
    size = (size + 7u) & ~(size_t)7u;
    if (size == 0) {
        size = 8;
    }
    arena_block *block = a->head;
    if (block == NULL || block->used + size > block->capacity) {
        size_t capacity = size > 8192u ? size : 8192u;
        block = malloc(sizeof(*block) + capacity);
        if (block == NULL) {
            return NULL;
        }
        block->next = a->head;
        block->capacity = capacity;
        block->used = 0;
        a->head = block;
    }
    void *result = block->data + block->used;
    block->used += size;
    return result;
}

static void arena_reset(arena *a) {
    arena_block *block = a->head;
    while (block != NULL) {
        arena_block *next = block->next;
        free(block);
        block = next;
    }
    a->head = NULL;
}

static char *arena_strndup(arena *a, const char *text, size_t length) {
    char *copy = arena_alloc(a, length + 1);
    if (copy == NULL) {
        return NULL;
    }
    if (length > 0) {
        memcpy(copy, text, length);
    }
    copy[length] = '\0';
    return copy;
}

/* ------------------------------------------------------------------- node */

typedef enum {
    NODE_SCALAR,
    NODE_MAP,
    NODE_SEQ
} node_kind;

typedef struct node node;

typedef struct {
    const char *key;
    node *value;
} pair;

struct node {
    node_kind kind;
    const char *text;
    pair *pairs;
    size_t npairs;
    size_t cap_pairs;
    node **items;
    size_t nitems;
    size_t cap_items;
};

static node *node_new(arena *a, node_kind kind) {
    node *n = arena_alloc(a, sizeof(*n));
    if (n == NULL) {
        return NULL;
    }
    memset(n, 0, sizeof(*n));
    n->kind = kind;
    return n;
}

static node *node_scalar(arena *a, const char *text) {
    node *n = node_new(a, NODE_SCALAR);
    if (n != NULL) {
        n->text = text;
    }
    return n;
}

static void map_add(arena *a, node *map, const char *key, node *value) {
    if (map->npairs == map->cap_pairs) {
        size_t capacity = map->cap_pairs == 0 ? 8u : map->cap_pairs * 2u;
        pair *grown = arena_alloc(a, capacity * sizeof(*grown));
        if (grown == NULL) {
            return;
        }
        if (map->npairs > 0) {
            memcpy(grown, map->pairs, map->npairs * sizeof(*grown));
        }
        map->pairs = grown;
        map->cap_pairs = capacity;
    }
    map->pairs[map->npairs].key = key;
    map->pairs[map->npairs].value = value;
    map->npairs++;
}

static void seq_add(arena *a, node *seq, node *item) {
    if (seq->nitems == seq->cap_items) {
        size_t capacity = seq->cap_items == 0 ? 8u : seq->cap_items * 2u;
        node **grown = arena_alloc(a, capacity * sizeof(*grown));
        if (grown == NULL) {
            return;
        }
        if (seq->nitems > 0) {
            memcpy(grown, seq->items, seq->nitems * sizeof(*grown));
        }
        seq->items = grown;
        seq->cap_items = capacity;
    }
    seq->items[seq->nitems++] = item;
}

static const node *map_get(const node *map, const char *key) {
    if (map == NULL || map->kind != NODE_MAP) {
        return NULL;
    }
    for (size_t i = 0; i < map->npairs; i++) {
        if (strcmp(map->pairs[i].key, key) == 0) {
            return map->pairs[i].value;
        }
    }
    return NULL;
}

/* --------------------------------------------------------------- parsing */

typedef struct {
    const char *text;
    int indent;
    size_t line;
} tline;

typedef struct {
    tline *items;
    size_t nitems;
    size_t capacity;
} tlines;

typedef struct {
    const char *path;
    tlines lines;
    size_t pos;
    arena *arena;
    int errors;
} parser;

static void parse_error(parser *p, size_t line, const char *format, ...) {
    char message[256];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    fprintf(stderr, "%s:%zu: %s\n", p->path, line, message);
    p->errors++;
}

static void lines_add(parser *p, const char *text, int indent, size_t line) {
    tlines *lines = &p->lines;
    if (lines->nitems == lines->capacity) {
        size_t capacity = lines->capacity == 0 ? 64u : lines->capacity * 2u;
        tline *grown = arena_alloc(p->arena, capacity * sizeof(*grown));
        if (grown == NULL) {
            return;
        }
        if (lines->nitems > 0) {
            memcpy(grown, lines->items, lines->nitems * sizeof(*grown));
        }
        lines->items = grown;
        lines->capacity = capacity;
    }
    lines->items[lines->nitems].text = text;
    lines->items[lines->nitems].indent = indent;
    lines->items[lines->nitems].line = line;
    lines->nitems++;
}

static void strip_comment(char *text) {
    int quote = 0;
    for (size_t i = 0; text[i] != '\0'; i++) {
        char c = text[i];
        if (quote != 0) {
            if (quote == '"' && c == '\\' && text[i + 1] != '\0') {
                i++;
                continue;
            }
            if (c == quote) {
                quote = 0;
            }
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            continue;
        }
        if (c == '#' && (i == 0 || text[i - 1] == ' ' || text[i - 1] == '\t')) {
            text[i] = '\0';
            return;
        }
    }
}

static char *trim_left(char *text) {
    while (*text == ' ' || *text == '\t') {
        text++;
    }
    return text;
}

static void trim_right(char *text) {
    size_t length = strlen(text);
    while (length > 0 && (text[length - 1] == ' ' || text[length - 1] == '\t')) {
        text[--length] = '\0';
    }
}

static int preprocess(parser *p, const char *text, size_t length) {
    char *copy = arena_alloc(p->arena, length + 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, text, length);
    copy[length] = '\0';

    size_t line_number = 0;
    char *cursor = copy;
    while (cursor != NULL && *cursor != '\0') {
        char *newline = strchr(cursor, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }
        line_number++;

        size_t raw_length = strlen(cursor);
        if (raw_length > 0 && cursor[raw_length - 1] == '\r') {
            cursor[raw_length - 1] = '\0';
        }
        strip_comment(cursor);
        trim_right(cursor);

        char *content = trim_left(cursor);
        int indent = (int)(content - cursor);
        if (*content != '\0') {
            int saw_tab = 0;
            for (int i = 0; i < indent; i++) {
                if (cursor[i] == '\t') {
                    saw_tab = 1;
                }
            }
            if (saw_tab) {
                parse_error(p, line_number, "tab indentation is not allowed");
            } else if (strcmp(content, "---") != 0 && strcmp(content, "...") != 0) {
                lines_add(p, content, indent, line_number);
            }
        }

        if (newline == NULL) {
            break;
        }
        cursor = newline + 1;
    }
    return p->errors == 0 ? 0 : -1;
}

static int starts_dash(const char *text) {
    return text[0] == '-' && (text[1] == '\0' || text[1] == ' ');
}

static size_t find_key_colon(const char *text) {
    int quote = 0;
    for (size_t i = 0; text[i] != '\0'; i++) {
        char c = text[i];
        if (quote != 0) {
            if (quote == '"' && c == '\\' && text[i + 1] != '\0') {
                i++;
                continue;
            }
            if (c == quote) {
                quote = 0;
            }
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            continue;
        }
        if (c == ':' && (text[i + 1] == '\0' || text[i + 1] == ' ')) {
            return i;
        }
    }
    return SIZE_MAX;
}

static int is_scalar_item(const char *content) {
    switch (content[0]) {
        case '!':
        case '[':
        case '{':
        case '\'':
        case '"':
            return 1;
        default:
            break;
    }
    return find_key_colon(content) == SIZE_MAX;
}

static node *parse_node(parser *p, int indent);

static node *parse_map(parser *p, int indent) {
    node *map = node_new(p->arena, NODE_MAP);
    if (map == NULL) {
        return NULL;
    }
    while (p->pos < p->lines.nitems) {
        tline *line = &p->lines.items[p->pos];
        if (line->indent < indent) {
            break;
        }
        if (line->indent > indent) {
            parse_error(p, line->line, "unexpected indentation");
            return NULL;
        }
        if (starts_dash(line->text)) {
            parse_error(p, line->line, "sequence item inside a mapping");
            return NULL;
        }
        size_t colon = find_key_colon(line->text);
        if (colon == SIZE_MAX) {
            parse_error(p, line->line, "expected a mapping key");
            return NULL;
        }
        char *key = arena_strndup(p->arena, line->text, colon);
        char *value = arena_strndup(p->arena, line->text + colon + 1,
                                    strlen(line->text + colon + 1));
        if (key == NULL || value == NULL) {
            return NULL;
        }
        trim_right(value);
        value = trim_left(value);
        p->pos++;

        node *child = NULL;
        if (*value == '\0') {
            if (p->pos < p->lines.nitems && p->lines.items[p->pos].indent > indent) {
                child = parse_node(p, p->lines.items[p->pos].indent);
            } else {
                child = node_scalar(p->arena, "");
            }
        } else {
            child = node_scalar(p->arena, value);
        }
        if (child == NULL) {
            return NULL;
        }
        map_add(p->arena, map, key, child);
    }
    return map;
}

static node *parse_seq(parser *p, int indent) {
    node *seq = node_new(p->arena, NODE_SEQ);
    if (seq == NULL) {
        return NULL;
    }
    while (p->pos < p->lines.nitems) {
        tline *line = &p->lines.items[p->pos];
        if (line->indent < indent) {
            break;
        }
        if (line->indent > indent) {
            parse_error(p, line->line, "unexpected indentation in sequence");
            return NULL;
        }
        if (!starts_dash(line->text)) {
            break;
        }
        const char *content = line->text + 1;
        if (*content == ' ') {
            content++;
        }
        node *item = NULL;
        if (*content == '\0') {
            p->pos++;
            if (p->pos < p->lines.nitems && p->lines.items[p->pos].indent > indent) {
                item = parse_node(p, p->lines.items[p->pos].indent);
            } else {
                item = node_scalar(p->arena, "");
            }
        } else if (is_scalar_item(content)) {
            item = node_scalar(p->arena, content);
            p->pos++;
        } else {
            line->text = content;
            line->indent = indent + 2;
            item = parse_node(p, indent + 2);
        }
        if (item == NULL) {
            return NULL;
        }
        seq_add(p->arena, seq, item);
    }
    return seq;
}

static node *parse_node(parser *p, int indent) {
    if (p->pos >= p->lines.nitems) {
        return node_scalar(p->arena, "");
    }
    if (starts_dash(p->lines.items[p->pos].text)) {
        return parse_seq(p, indent);
    }
    return parse_map(p, indent);
}

/* --------------------------------------------------------------- scalars */

static int raw_equals(const char *raw, const char *want) {
    size_t length = strlen(raw);
    if (length >= 2) {
        char first = raw[0];
        char last = raw[length - 1];
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            raw++;
            length -= 2;
        }
    }
    return length == strlen(want) && memcmp(raw, want, length) == 0;
}

static size_t raw_unquote(const char *raw, char *out, size_t capacity) {
    size_t length = strlen(raw);
    if (length >= 2) {
        char first = raw[0];
        char last = raw[length - 1];
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            raw++;
            length -= 2;
        }
    }
    if (length >= capacity) {
        length = capacity - 1;
    }
    memcpy(out, raw, length);
    out[length] = '\0';
    return length;
}

static int node_scalar_equals(const node *n, const char *want) {
    return n != NULL && n->kind == NODE_SCALAR && raw_equals(n->text, want);
}

static size_t scalar_count(const node *n) {
    if (n == NULL) {
        return 0;
    }
    if (n->kind == NODE_SCALAR) {
        return 1;
    }
    return n->kind == NODE_SEQ ? n->nitems : 0;
}

static const node *scalar_at(const node *n, size_t index) {
    if (n == NULL) {
        return NULL;
    }
    if (n->kind == NODE_SCALAR) {
        return index == 0 ? n : NULL;
    }
    if (n->kind == NODE_SEQ && index < n->nitems) {
        return n->items[index];
    }
    return NULL;
}

static int node_contains(const node *n, const char *needle) {
    if (n == NULL) {
        return 0;
    }
    if (n->kind == NODE_SCALAR) {
        return n->text != NULL && strstr(n->text, needle) != NULL;
    }
    if (n->kind == NODE_MAP) {
        for (size_t i = 0; i < n->npairs; i++) {
            if (strstr(n->pairs[i].key, needle) != NULL) {
                return 1;
            }
            if (node_contains(n->pairs[i].value, needle)) {
                return 1;
            }
        }
        return 0;
    }
    for (size_t i = 0; i < n->nitems; i++) {
        if (node_contains(n->items[i], needle)) {
            return 1;
        }
    }
    return 0;
}

static int token_with_boundary(const char *text, const char *pattern) {
    size_t length = strlen(pattern);
    const char *cursor = text;
    while ((cursor = strstr(cursor, pattern)) != NULL) {
        char next = cursor[length];
        if (next == '\0' || next == ' ' || next == ',' || next == ']' ||
            next == '}' || next == ')' || next == '\n') {
            return 1;
        }
        cursor++;
    }
    return 0;
}

static int scalar_references(const char *text, const char *name) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "!Ref %s", name);
    if (token_with_boundary(text, pattern)) {
        return 1;
    }
    snprintf(pattern, sizeof(pattern), "${%s}", name);
    if (strstr(text, pattern) != NULL) {
        return 1;
    }
    snprintf(pattern, sizeof(pattern), "!GetAtt %s.", name);
    if (strstr(text, pattern) != NULL) {
        return 1;
    }
    return 0;
}

static int node_references(const node *n, const char *name) {
    if (n == NULL) {
        return 0;
    }
    if (n->kind == NODE_SCALAR) {
        return scalar_references(n->text, name);
    }
    if (n->kind == NODE_MAP) {
        for (size_t i = 0; i < n->npairs; i++) {
            const pair *entry = &n->pairs[i];
            if (strcmp(entry->key, "Ref") == 0 && node_scalar_equals(entry->value, name)) {
                return 1;
            }
            if (node_references(entry->value, name)) {
                return 1;
            }
        }
        return 0;
    }
    for (size_t i = 0; i < n->nitems; i++) {
        if (node_references(n->items[i], name)) {
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------ diagnostics */

typedef struct {
    const char *path;
    int violations;
} checker;

static void violation(checker *c, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%s: ", c->path);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    c->violations++;
}

/* ------------------------------------------------------------- IAM checks */

static const char *const STAR_ALLOWED_ACTIONS[] = {
    "cloudformation:GetTemplateSummary",
    "ec2:DescribeInstances",
    "ec2:DescribeImages",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSecurityGroupRules",
    "ec2:DescribeKeyPairs",
    "ec2:DescribeVolumes",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeSpotPriceHistory",
    /* VPC-lifecycle reads the CFN resource handlers issue under the caller's
     * identity (same read-only class as the entries above). */
    "ec2:DescribeInternetGateways",
    "ec2:DescribeRouteTables",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeTags",
    "ec2:DescribeVpcAttribute",
    "ec2:DescribeSubnetAttribute",
};

static int action_star_allowed(const char *action) {
    for (size_t i = 0; i < sizeof(STAR_ALLOWED_ACTIONS) / sizeof(STAR_ALLOWED_ACTIONS[0]); i++) {
        if (raw_equals(action, STAR_ALLOWED_ACTIONS[i])) {
            return 1;
        }
    }
    return 0;
}

static int action_list_contains(const node *action, const char *want) {
    for (size_t i = 0; i < scalar_count(action); i++) {
        const node *entry = scalar_at(action, i);
        if (entry != NULL && node_scalar_equals(entry, want)) {
            return 1;
        }
    }
    return 0;
}

static int action_list_all_star_allowed(const node *action) {
    size_t count = scalar_count(action);
    if (count == 0) {
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        const node *entry = scalar_at(action, i);
        if (entry == NULL || !action_star_allowed(entry->text)) {
            return 0;
        }
    }
    return 1;
}

static void check_action_text(checker *c, const char *raw) {
    if (raw[0] == '!') {
        violation(c, "IAM Action is not a static value: %s", raw);
        return;
    }
    char action[256];
    raw_unquote(raw, action, sizeof(action));
    if (action[0] == '\0') {
        violation(c, "empty IAM Action");
        return;
    }
    if (strchr(action, '*') != NULL) {
        violation(c, "wildcard IAM Action is forbidden: %s", action);
        return;
    }
    if (strchr(action, ':') == NULL) {
        violation(c, "IAM Action is not service-qualified: %s", action);
    }
}

static int resource_literal(const char *raw, char *out, size_t capacity, int *opaque) {
    *opaque = 0;
    if (strncmp(raw, "!Ref", 4) == 0 || strncmp(raw, "!GetAtt", 7) == 0) {
        *opaque = 1;
        return 0;
    }
    const char *source = raw;
    if (strncmp(raw, "!Sub", 4) == 0) {
        source = raw + 4;
        while (*source == ' ') {
            source++;
        }
    } else if (raw[0] == '!' || raw[0] == '[' || raw[0] == '{') {
        *opaque = 2;
        return 0;
    }
    raw_unquote(source, out, capacity);
    return 1;
}

static void check_resource_text(checker *c, const char *raw, int star_allowed) {
    char literal[1024];
    int opaque = 0;
    if (resource_literal(raw, literal, sizeof(literal), &opaque) == 0) {
        if (opaque == 2) {
            violation(c, "IAM Resource is not statically scoped: %s", raw);
        }
        return;
    }
    if (strcmp(literal, "*") == 0) {
        if (!star_allowed) {
            violation(c, "wildcard IAM Resource is forbidden for this action set");
        }
        return;
    }
    if (literal[0] == '\0') {
        violation(c, "empty IAM Resource");
        return;
    }
    if (strncmp(literal, "arn:aws:", 8) != 0 && strncmp(literal, "arn:aws-cn:", 11) != 0) {
        violation(c, "IAM Resource is not an ARN: %s", literal);
        return;
    }
    if (strcmp(literal, "arn:aws:s3:::*") == 0) {
        violation(c, "bucket-wide S3 Resource is forbidden: %s", literal);
    }
}

/*
 * Action/Resource values can be long-form intrinsics ({"Fn::If": [...]},
 * {"Fn::Sub": "..."}, {"Fn::Join": [...]}, {"Ref": ...}).  Walking the raw
 * scalar list only would make the checker fail open: a map has no scalars, so
 * `Action: {Fn::If: [cond, "*", "s3:GetObject"]}` used to bypass the wildcard
 * check.  These walkers understand the intrinsic shapes the templates and
 * TEMPLATE_OVERRIDE files may carry and reject anything they cannot prove.
 */

static int join_intrinsic_scalars(const node *join, char *out, size_t capacity) {
    /* Fn::Join shape: [delimiter, [part, part, ...]] */
    if (join->kind != NODE_SEQ || join->nitems != 2 ||
        join->items[0]->kind != NODE_SCALAR || join->items[1]->kind != NODE_SEQ) {
        return 0;
    }
    char delimiter[32];
    raw_unquote(join->items[0]->text, delimiter, sizeof(delimiter));
    const node *parts = join->items[1];
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < parts->nitems; i++) {
        const node *part = parts->items[i];
        if (part->kind != NODE_SCALAR) {
            return 0;
        }
        char piece[512];
        raw_unquote(part->text, piece, sizeof(piece));
        size_t piece_len = strlen(piece);
        size_t delim_len = i == 0 ? 0 : strlen(delimiter);
        if (used + delim_len + piece_len + 1 > capacity) {
            return 0;
        }
        if (delim_len > 0) {
            memcpy(out + used, delimiter, delim_len);
            used += delim_len;
        }
        memcpy(out + used, piece, piece_len);
        used += piece_len;
        out[used] = '\0';
    }
    return 1;
}

static void check_action_node(checker *c, const node *n) {
    if (n == NULL) {
        violation(c, "IAM Action is missing");
        return;
    }
    if (n->kind == NODE_SCALAR) {
        check_action_text(c, n->text);
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            check_action_node(c, n->items[i]);
        }
        return;
    }
    const node *fn_if = map_get(n, "Fn::If");
    if (fn_if != NULL) {
        if (fn_if->kind != NODE_SEQ || fn_if->nitems != 3) {
            violation(c, "IAM Action Fn::If must have [condition, then, else]");
            return;
        }
        check_action_node(c, fn_if->items[1]);
        check_action_node(c, fn_if->items[2]);
        return;
    }
    /* Ref / Fn::Sub / Fn::Join / unknown shapes cannot be proven static. */
    violation(c, "IAM Action is not a static value");
}

static void check_resource_node(checker *c, const node *n, int star_allowed) {
    if (n == NULL) {
        return;
    }
    if (n->kind == NODE_SCALAR) {
        check_resource_text(c, n->text, star_allowed);
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            check_resource_node(c, n->items[i], star_allowed);
        }
        return;
    }
    const node *fn_if = map_get(n, "Fn::If");
    if (fn_if != NULL) {
        if (fn_if->kind != NODE_SEQ || fn_if->nitems != 3) {
            violation(c, "IAM Resource Fn::If must have [condition, then, else]");
            return;
        }
        check_resource_node(c, fn_if->items[1], star_allowed);
        check_resource_node(c, fn_if->items[2], star_allowed);
        return;
    }
    const node *fn_sub = map_get(n, "Fn::Sub");
    if (fn_sub != NULL) {
        if (fn_sub->kind == NODE_SCALAR) {
            check_resource_text(c, fn_sub->text, star_allowed);
            return;
        }
        /* Only the scalar template-string form is trustworthy. A sequence form
         * carries a substitution map that can rebind ${ProjectName} or
         * ${AWS::AccountId}, so the visible template is not the final ARN. */
        if (fn_sub->kind == NODE_SEQ && fn_sub->nitems == 1 &&
            fn_sub->items[0]->kind == NODE_SCALAR) {
            check_resource_text(c, fn_sub->items[0]->text, star_allowed);
            return;
        }
        violation(c, "IAM Resource Fn::Sub has an unsupported shape");
        return;
    }
    const node *fn_join = map_get(n, "Fn::Join");
    if (fn_join != NULL) {
        char joined[2048];
        if (join_intrinsic_scalars(fn_join, joined, sizeof(joined))) {
            check_resource_text(c, joined, star_allowed);
        } else {
            violation(c, "IAM Resource Fn::Join has an unsupported shape");
        }
        return;
    }
    if (map_get(n, "Ref") != NULL) {
        /* A Ref to a parameter/attribute is opaque but is the documented
         * template form for a caller-supplied ARN. */
        return;
    }
    violation(c, "IAM Resource uses an unsupported intrinsic");
}

/*
 * The S3-scope and CI-reader rules reason about the concrete Action/Resource
 * literals a policy grants.  Resolving an intrinsic node to that literal set
 * lets those rules keep their scalar checks while still failing closed on the
 * long-form shapes ({Fn::If}, {Ref}, {Fn::Sub}, {Fn::Join}) that a scalar-only
 * walk silently drops.  Any shape that cannot be resolved records an
 * unsupported_shape, which every caller treats as a violation.
 */

#define RESOLVED_MAX 64

typedef struct {
    const char *literal;
    int from_sub;
    const char *shape;
} resolved_value;

typedef struct {
    resolved_value values[RESOLVED_MAX];
    char storage[RESOLVED_MAX][1024];
    size_t count;
    const char *unsupported_shape;
} resolution;

static void resolved_add(resolution *r, const char *literal, int from_sub,
                         const char *shape) {
    if (r->count >= RESOLVED_MAX) {
        if (r->unsupported_shape == NULL) {
            r->unsupported_shape = "too many values";
        }
        return;
    }
    size_t index = r->count++;
    snprintf(r->storage[index], sizeof(r->storage[index]), "%s", literal);
    r->values[index].literal = r->storage[index];
    r->values[index].from_sub = from_sub;
    r->values[index].shape = shape;
}

static void resolved_add_sub(resolution *r, const node *value, const char *shape) {
    char literal[1024];
    raw_unquote(value->text, literal, sizeof(literal));
    resolved_add(r, literal, 1, shape);
}

static void resolve_node(const node *n, resolution *r) {
    if (n == NULL || r->unsupported_shape != NULL) {
        return;
    }
    if (n->kind == NODE_SCALAR) {
        const char *text = n->text != NULL ? n->text : "";
        if (strncmp(text, "!Sub", 4) == 0 && (text[4] == '\0' || text[4] == ' ')) {
            const char *source = text + 4;
            while (*source == ' ') {
                source++;
            }
            char literal[1024];
            raw_unquote(source, literal, sizeof(literal));
            resolved_add(r, literal, 1, "!Sub");
            return;
        }
        if (text[0] == '!') {
            r->unsupported_shape = text;
            return;
        }
        char literal[1024];
        raw_unquote(text, literal, sizeof(literal));
        resolved_add(r, literal, 0, "literal");
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            resolve_node(n->items[i], r);
        }
        return;
    }

    const node *fn_if = map_get(n, "Fn::If");
    if (fn_if != NULL) {
        if (fn_if->kind != NODE_SEQ || fn_if->nitems != 3) {
            r->unsupported_shape = "Fn::If";
            return;
        }
        resolve_node(fn_if->items[1], r);
        resolve_node(fn_if->items[2], r);
        return;
    }
    const node *fn_sub = map_get(n, "Fn::Sub");
    if (fn_sub != NULL) {
        if (fn_sub->kind == NODE_SCALAR) {
            resolved_add_sub(r, fn_sub, "Fn::Sub");
            return;
        }
        /* The sequence form carries a substitution map that can rebind the
         * contract placeholders; it must fail closed rather than trust the
         * template string. Do not attempt to resolve substitution maps. */
        if (fn_sub->kind == NODE_SEQ && fn_sub->nitems == 1 &&
            fn_sub->items[0]->kind == NODE_SCALAR) {
            resolved_add_sub(r, fn_sub->items[0], "Fn::Sub");
            return;
        }
        r->unsupported_shape = "Fn::Sub";
        return;
    }
    const node *fn_join = map_get(n, "Fn::Join");
    if (fn_join != NULL) {
        char joined[2048];
        if (join_intrinsic_scalars(fn_join, joined, sizeof(joined))) {
            resolved_add(r, joined, 0, "Fn::Join");
        } else {
            r->unsupported_shape = "Fn::Join";
        }
        return;
    }
    if (map_get(n, "Ref") != NULL) {
        r->unsupported_shape = "Ref";
        return;
    }
    r->unsupported_shape = "unsupported intrinsic map";
}

static int resolved_has(const resolution *r, const char *want) {
    for (size_t i = 0; i < r->count; i++) {
        if (strcmp(r->values[i].literal, want) == 0) {
            return 1;
        }
    }
    return 0;
}

static void check_iam_node(checker *c, const node *n) {
    if (n == NULL) {
        return;
    }
    if (n->kind == NODE_MAP) {
        const node *action = map_get(n, "Action");
        const node *resource = map_get(n, "Resource");
        if (action != NULL) {
            check_action_node(c, action);
            if (resource != NULL) {
                int star_allowed = action_list_all_star_allowed(action);
                check_resource_node(c, resource, star_allowed);
            }
        }
        for (size_t i = 0; i < n->npairs; i++) {
            check_iam_node(c, n->pairs[i].value);
        }
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            check_iam_node(c, n->items[i]);
        }
    }
}

static const node *find_statement(const node *n, const char *action) {
    if (n == NULL) {
        return NULL;
    }
    if (n->kind == NODE_MAP) {
        const node *actions = map_get(n, "Action");
        if (actions != NULL && action_list_contains(actions, action)) {
            return n;
        }
        for (size_t i = 0; i < n->npairs; i++) {
            const node *found = find_statement(n->pairs[i].value, action);
            if (found != NULL) {
                return found;
            }
        }
    } else if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            const node *found = find_statement(n->items[i], action);
            if (found != NULL) {
                return found;
            }
        }
    }
    return NULL;
}

static const node *find_statement_with_condition(const node *n, const char *action,
                                                 const char *needle) {
    if (n == NULL) {
        return NULL;
    }
    if (n->kind == NODE_MAP) {
        const node *actions = map_get(n, "Action");
        const node *condition = map_get(n, "Condition");
        if (actions != NULL && action_list_contains(actions, action) &&
            condition != NULL && node_contains(condition, needle)) {
            return n;
        }
        for (size_t i = 0; i < n->npairs; i++) {
            const node *found = find_statement_with_condition(n->pairs[i].value, action, needle);
            if (found != NULL) {
                return found;
            }
        }
    } else if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            const node *found = find_statement_with_condition(n->items[i], action, needle);
            if (found != NULL) {
                return found;
            }
        }
    }
    return NULL;
}

static int template_has_action(const node *n, const char *action) {
    return find_statement(n, action) != NULL;
}

/* ------------------------------------------------------- shared structure */

static const node *template_resources(const node *root) {
    return map_get(root, "Resources");
}

static const node *template_parameters(const node *root) {
    return map_get(root, "Parameters");
}

static const node *template_outputs(const node *root) {
    return map_get(root, "Outputs");
}

static int resource_is_type(const node *resource, const char *type);

static void check_sections(checker *c, const node *root) {
    if (root == NULL || root->kind != NODE_MAP) {
        violation(c, "template root must be a mapping");
        return;
    }
    if (template_parameters(root) == NULL) {
        violation(c, "missing Parameters section");
    }
    if (template_resources(root) == NULL) {
        violation(c, "missing Resources section");
    }
    if (template_outputs(root) == NULL) {
        violation(c, "missing Outputs section");
    }
}

static void check_required_params(checker *c, const node *root,
                                  const char *const *names, size_t count) {
    const node *params = template_parameters(root);
    for (size_t i = 0; i < count; i++) {
        const node *param = map_get(params, names[i]);
        if (param == NULL) {
            violation(c, "missing required parameter %s", names[i]);
            continue;
        }
        if (!node_references(root, names[i])) {
            violation(c, "required parameter %s is present but never referenced", names[i]);
        }
    }
}

static void check_required_outputs(checker *c, const node *root,
                                   const char *const *names, size_t count) {
    const node *outputs = template_outputs(root);
    for (size_t i = 0; i < count; i++) {
        const node *output = map_get(outputs, names[i]);
        if (output == NULL) {
            violation(c, "missing required output %s", names[i]);
            continue;
        }
        const node *value = map_get(output, "Value");
        if (value == NULL) {
            violation(c, "required output %s has no Value", names[i]);
            continue;
        }
        if (value->kind == NODE_SCALAR) {
            char text[256];
            raw_unquote(value->text, text, sizeof(text));
            if (text[0] == '\0') {
                violation(c, "required output %s is empty", names[i]);
            }
        }
    }
}

static void check_no_exports(checker *c, const node *root) {
    const node *outputs = template_outputs(root);
    if (outputs == NULL || outputs->kind != NODE_MAP) {
        return;
    }
    for (size_t i = 0; i < outputs->npairs; i++) {
        if (map_get(outputs->pairs[i].value, "Export") != NULL) {
            violation(c, "CloudFormation Exports are forbidden (output %s)",
                      outputs->pairs[i].key);
        }
    }
}

static void check_required_actions(checker *c, const node *root,
                                   const char *const *names, size_t count) {
    const node *resources = template_resources(root);
    for (size_t i = 0; i < count; i++) {
        if (!template_has_action(resources, names[i])) {
            violation(c, "operator policy is missing required action %s", names[i]);
        }
    }
}

static void check_project_name_drives_names(checker *c, const node *root) {
    const node *resources = template_resources(root);
    if (!node_contains(resources, "${ProjectName}") &&
        !node_contains(resources, "!Ref ProjectName")) {
        violation(c, "ProjectName does not drive any resource name");
    }
}

static void check_stack_name_contract(checker *c, const node *root) {
    const node *params = template_parameters(root);
    if (map_get(params, "ProjectName") == NULL) {
        violation(c, "stack name contract requires a ProjectName parameter");
    }
    check_project_name_drives_names(c, root);
}

/* ------------------------------------------------------------- operator */

static const char *const OPERATOR_PARAMS[] = {
    "ProjectName",
    "InstanceTypeAllowlist",
    "EnableImageBuilder",
    "CertBucketEnabled",
};

static const char *const OPERATOR_OUTPUTS[] = {
    "InstanceRoleArn",
    "InstanceProfileArn",
};

static const char *const OPERATOR_ACTIONS[] = {
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "ec2:CreateTags",
    "ec2:GetConsoleOutput",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:DeleteAccessKey",
    "cloudformation:GetTemplateSummary",
    "cloudformation:CreateChangeSet",
    "cloudformation:DescribeChangeSet",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:DeleteChangeSet",
    "cloudformation:DeleteStack",
    "ssm:GetParameter",
    "s3:PutObject",
    "s3:GetObject",
    "s3:DeleteObject",
    "s3:ListBucket",
};

static void check_tag_key_allowlist(checker *c, const node *statement) {
    const node *condition = map_get(statement, "Condition");
    if (condition == NULL) {
        return;
    }
    const node *for_all = map_get(condition, "ForAllValues:StringEquals");
    const node *tag_keys = map_get(for_all, "aws:TagKeys");
    if (tag_keys == NULL) {
        return;
    }
    static const char *const allowed[] = {"Project", "Name", "stackctl:launch-nonce"};
    for (size_t i = 0; i < scalar_count(tag_keys); i++) {
        const node *entry = scalar_at(tag_keys, i);
        if (entry == NULL) {
            continue;
        }
        int matched = 0;
        for (size_t j = 0; j < sizeof(allowed) / sizeof(allowed[0]); j++) {
            if (node_scalar_equals(entry, allowed[j])) {
                matched = 1;
            }
        }
        if (!matched) {
            violation(c, "CreateTags may tag with a key outside the launch allowlist: %s",
                      entry->text);
        }
    }
}

static int cert_policy_is_conditional(const node *role) {
    const node *properties = map_get(role, "Properties");
    const node *policies = map_get(properties, "Policies");
    if (policies == NULL || policies->kind != NODE_SEQ) {
        return 0;
    }
    for (size_t i = 0; i < policies->nitems; i++) {
        const node *policy = policies->items[i];
        if (!node_contains(policy, "-certs-")) {
            continue;
        }
        return policy->kind == NODE_MAP && map_get(policy, "Fn::If") != NULL;
    }
    return 0;
}

#define OPERATOR_MAX_POLICIES 8

typedef struct {
    const node *items[OPERATOR_MAX_POLICIES];
    /* NULL when the policy reaches the user through ManagedPolicyArns;
     * otherwise the Users/Roles/Groups section that names the operator user.
     * The label makes a gap-closing violation distinguishable in diagnostics. */
    const char *attachments[OPERATOR_MAX_POLICIES];
    size_t count;
    /* Policies discovered past the fixed inspection cap. The union is then
     * only partially inspected, so the caller must fail closed. */
    size_t overflowed;
} operator_policies;

static operator_policies collect_operator_policies(const node *root);

/*
 * The operator policy may grant bucket-lifecycle actions on the cert bucket
 * because CloudFormation's S3 handlers create and configure it under the
 * caller's identity, but it must never grant object CONTENT access: the cert
 * store is written only by the conditional instance-role policy. s3:ListBucket
 * is bucket-level (HeadBucket) and exposes no object contents, so the handler
 * lifecycle statement may carry it.
 */
static int grants_cert_object_access(const node *n) {
    if (n == NULL) {
        return 0;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            if (grants_cert_object_access(n->items[i])) {
                return 1;
            }
        }
        return 0;
    }
    if (n->kind != NODE_MAP) {
        return 0;
    }
    const node *action = map_get(n, "Action");
    const node *resource = map_get(n, "Resource");
    if (action != NULL && resource != NULL && node_contains(resource, "-certs-")) {
        if (action_list_contains(action, "s3:GetObject") ||
            action_list_contains(action, "s3:PutObject") ||
            action_list_contains(action, "s3:DeleteObject")) {
            return 1;
        }
    }
    for (size_t i = 0; i < n->npairs; i++) {
        if (grants_cert_object_access(n->pairs[i].value)) {
            return 1;
        }
    }
    return 0;
}

static void check_operator_role_resources(checker *c, const node *root) {
    const node *resources = template_resources(root);
    const node *role = map_get(resources, "InstanceRole");
    if (role == NULL) {
        violation(c, "missing InstanceRole resource");
    } else {
        const node *properties = map_get(role, "Properties");
        const node *assume = map_get(properties, "AssumeRolePolicyDocument");
        if (assume == NULL || !node_contains(assume, "sts:AssumeRole")) {
            violation(c, "InstanceRole is missing an ec2 trust policy");
        }
        if (!node_contains(role, "-certs-")) {
            violation(c, "InstanceRole is missing the cert-store inline policy");
        } else if (!cert_policy_is_conditional(role)) {
            violation(c, "cert-store inline policy must be conditional on the cert bucket module");
        }
    }

    const node *profile = map_get(resources, "InstanceProfile");
    if (profile == NULL) {
        violation(c, "missing InstanceProfile resource");
    } else {
        const node *properties = map_get(profile, "Properties");
        if (map_get(properties, "Roles") == NULL || !node_contains(profile, "InstanceRole")) {
            violation(c, "InstanceProfile does not reference InstanceRole");
        }
    }

    if (map_get(resources, "OperatorPolicy") == NULL) {
        violation(c, "missing OperatorPolicy resource");
        return;
    }
    const operator_policies operator = collect_operator_policies(root);
    for (size_t i = 0; i < operator.count; i++) {
        if (grants_cert_object_access(operator.items[i])) {
            violation(c, "operator policies must never grant object access to the cert bucket");
            return;
        }
    }
}

/* CONTRACT grant model: every operator S3 resource is a !Sub literal on the
 * project bucket, bucket ARN without the object suffix and objects with it. */
#define OWN_ARTIFACT_BUCKET_PREFIX "arn:aws:s3:::${ProjectName}-artifacts-${AWS::AccountId}-"
#define OWN_ARTIFACT_BUCKET_ARN "arn:aws:s3:::${ProjectName}-artifacts-${AWS::AccountId}-*"
#define OWN_ARTIFACT_OBJECT_ARN OWN_ARTIFACT_BUCKET_PREFIX "*/*"
/* The certs bucket keeps its existing grants; the bucket handler may list it. */
#define OWN_CERT_BUCKET_ARN "arn:aws:s3:::${ProjectName}-certs-${AWS::AccountId}-*"

/* attachment is NULL for a policy reached through ManagedPolicyArns, else the
 * Users/Roles/Groups section that named the operator user. */
static void check_operator_s3_scope(checker *c, const node *n, const char *attachment) {
    if (n == NULL) {
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            check_operator_s3_scope(c, n->items[i], attachment);
        }
        return;
    }
    if (n->kind != NODE_MAP) {
        return;
    }

    char via[48] = "";
    if (attachment != NULL) {
        snprintf(via, sizeof(via), " (attached via %s)", attachment);
    }
    if (map_get(n, "NotAction") != NULL) {
        violation(c, "operator S3 policy uses an unsupported negated form "
                     "(NotAction)%s", via);
    }
    if (map_get(n, "NotResource") != NULL) {
        violation(c, "operator S3 policy uses an unsupported negated form "
                     "(NotResource)%s", via);
    }

    const node *action = map_get(n, "Action");
    const node *resource = map_get(n, "Resource");
    if (action != NULL) {
        resolution actions = {0};
        resolve_node(action, &actions);
        if (actions.unsupported_shape != NULL) {
            violation(c, "operator S3 policy Action uses an unsupported intrinsic "
                         "shape%s: %s",
                      via, actions.unsupported_shape);
        } else {
            /* The CloudFormation bucket handler needs an unscoped s3:ListBucket
             * (HeadBucket) while it creates/deletes the bucket. That statement
             * is identified by its co-located bucket lifecycle write grants. */
            const int bucket_handler_statement =
                resolved_has(&actions, "s3:CreateBucket") &&
                resolved_has(&actions, "s3:DeleteBucket");
            const int list_bucket = resolved_has(&actions, "s3:ListBucket");
            const int object_action = resolved_has(&actions, "s3:GetObject") ||
                                      resolved_has(&actions, "s3:PutObject") ||
                                      resolved_has(&actions, "s3:DeleteObject");
            if (resource != NULL && (list_bucket || object_action)) {
                resolution resources = {0};
                resolve_node(resource, &resources);
                if (resources.unsupported_shape != NULL) {
                    /* Rule 2: ListBucket needs no s3:prefix condition, but its
                     * resource must be exactly the own project bucket ARN (or
                     * the certs bucket for the bucket-handler statement). An
                     * unresolved shape cannot be proven to be either. */
                    if (list_bucket) {
                        violation(c, "operator ListBucket resource must be the own "
                                     "project artifact bucket ARN%s: unsupported "
                                     "intrinsic %s",
                                  via, resources.unsupported_shape);
                    }
                    /* Rule 1: object grants must be an own-project !Sub literal
                     * ending in the object wildcard. */
                    if (object_action) {
                        violation(c, "operator S3 object resource is not an "
                                     "own-project !Sub literal%s: unsupported "
                                     "intrinsic %s",
                                  via, resources.unsupported_shape);
                    }
                } else {
                    for (size_t i = 0; i < resources.count; i++) {
                        const resolved_value *value = &resources.values[i];
                        /* The bucket-handler exemption is not blanket: it may
                         * list only the own project bucket or the certs bucket.
                         * Any other bucket resource is still a rule-2 breach. */
                        const int list_bucket_allowed =
                            strcmp(value->literal, OWN_ARTIFACT_BUCKET_ARN) == 0 ||
                            (bucket_handler_statement &&
                             strcmp(value->literal, OWN_CERT_BUCKET_ARN) == 0);
                        if (list_bucket && !list_bucket_allowed) {
                            violation(c, "operator ListBucket resource must be the "
                                         "own project artifact bucket ARN%s: %s (%s)",
                                      via, value->literal, value->shape);
                        }
                        if (object_action &&
                            (!value->from_sub ||
                             strcmp(value->literal, OWN_ARTIFACT_OBJECT_ARN) != 0)) {
                            violation(c, "operator S3 object resource is not an "
                                         "own-project !Sub literal%s: %s (%s)",
                                      via, value->literal, value->shape);
                        }
                    }
                }
            }
        }
    }
    for (size_t i = 0; i < n->npairs; i++) {
        check_operator_s3_scope(c, n->pairs[i].value, attachment);
    }
}

/* Rule 4: the CI ArtifactReaderPolicy may only read. It grants GetObject on
 * the own project's objects and ListBucket on the own project's bucket; any
 * Put/Delete or other bucket is a violation. */
static void check_reader_statement(checker *c, const node *n) {
    if (n == NULL) {
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            check_reader_statement(c, n->items[i]);
        }
        return;
    }
    if (n->kind != NODE_MAP) {
        return;
    }
    if (map_get(n, "NotAction") != NULL) {
        violation(c, "ArtifactReaderPolicy uses an unsupported negated form "
                     "(NotAction)");
    }
    if (map_get(n, "NotResource") != NULL) {
        violation(c, "ArtifactReaderPolicy uses an unsupported negated form "
                     "(NotResource)");
    }
    const node *action = map_get(n, "Action");
    const node *resource = map_get(n, "Resource");
    if (action != NULL) {
        resolution actions = {0};
        resolve_node(action, &actions);
        if (actions.unsupported_shape != NULL) {
            violation(c, "ArtifactReaderPolicy Action uses an unsupported "
                         "intrinsic shape: %s",
                      actions.unsupported_shape);
        } else {
            for (size_t i = 0; i < actions.count; i++) {
                const resolved_value *value = &actions.values[i];
                int get_object = strcmp(value->literal, "s3:GetObject") == 0;
                int list_bucket = strcmp(value->literal, "s3:ListBucket") == 0;
                if (!get_object && !list_bucket) {
                    violation(c, "ArtifactReaderPolicy may grant only s3:GetObject "
                                 "and s3:ListBucket, found %s",
                              value->literal);
                    continue;
                }
                if (resource == NULL) {
                    continue;
                }
                resolution resources = {0};
                resolve_node(resource, &resources);
                if (resources.unsupported_shape != NULL) {
                    violation(c, "ArtifactReaderPolicy %s resource must be an "
                                 "own-project !Sub literal: unsupported intrinsic %s",
                              get_object ? "GetObject" : "ListBucket",
                              resources.unsupported_shape);
                    continue;
                }
                for (size_t j = 0; j < resources.count; j++) {
                    const resolved_value *target = &resources.values[j];
                    if (get_object &&
                        (!target->from_sub ||
                         strcmp(target->literal, OWN_ARTIFACT_OBJECT_ARN) != 0)) {
                        violation(c, "ArtifactReaderPolicy GetObject resource must "
                                     "be an own-project !Sub literal: %s (%s)",
                                  target->literal, target->shape);
                    } else if (list_bucket &&
                               strcmp(target->literal, OWN_ARTIFACT_BUCKET_ARN) != 0) {
                        violation(c, "ArtifactReaderPolicy ListBucket resource must "
                                     "be the own project artifact bucket ARN: %s (%s)",
                                  target->literal, target->shape);
                    }
                }
            }
        }
    }
    for (size_t i = 0; i < n->npairs; i++) {
        check_reader_statement(c, n->pairs[i].value);
    }
}

/* Rule 4 keys on the project-scoped CI identity (CONTRACT: `<project>-ci`).
 * The identity can be a User, Role, or Group; a policy reaches it through
 * Users/Roles/Groups (by logical id or exact emitted name), through the
 * identity's own ManagedPolicyArns, through its inline Policies, or through
 * membership of a group the CI user joins (UserToGroupAddition). Every one of
 * those paths is a CI-reader grant and is held to the read-only rule. */
#define CI_IDENTITY_NAME "${ProjectName}-ci"
#define CI_IDENTITY_MAX 16

typedef struct {
    const char *logical_id;
    const char *name_field;
    char name[256];
    int has_name;
} ci_identity;

typedef struct {
    ci_identity items[CI_IDENTITY_MAX];
    size_t count;
    int overflowed;
    /* A User/Role/Group whose declared name cannot be resolved to an exact
     * literal could be the CI identity; the caller fails closed and names the
     * first such resource. */
    int unresolved_names;
    const char *unresolved_name_id;
} ci_identities;

static const char *ci_identity_name_field(const node *resource) {
    if (resource_is_type(resource, "AWS::IAM::User")) {
        return "UserName";
    }
    if (resource_is_type(resource, "AWS::IAM::Role")) {
        return "RoleName";
    }
    if (resource_is_type(resource, "AWS::IAM::Group")) {
        return "GroupName";
    }
    return NULL;
}

static const char *skip_name_spaces(const char *text) {
    while (*text == ' ' || *text == '\t') {
        text++;
    }
    return text;
}

/* Resolves one scalar piece of a name (a literal, a quoted string, or
 * `!Ref ProjectName`). Resource refs are not names, so they stay unresolved. */
static int resolve_name_piece(const char *text, char *out, size_t capacity) {
    out[0] = '\0';
    text = skip_name_spaces(text);
    if (strncmp(text, "!Ref", 4) == 0 &&
        (text[4] == ' ' || text[4] == '\t')) {
        const char *target = skip_name_spaces(text + 4);
        if (strcmp(target, "ProjectName") == 0) {
            snprintf(out, capacity, "${ProjectName}");
            return 1;
        }
        return 0;
    }
    if (text[0] == '!') {
        return 0;
    }
    while (*text == ' ' || *text == '\t') {
        text++;
    }
    raw_unquote(text, out, capacity);
    size_t length = strlen(out);
    while (length > 0 && (out[length - 1] == ' ' || out[length - 1] == '\t')) {
        out[--length] = '\0';
    }
    return 1;
}

static int sub_variable_is_known(const char *name, size_t length) {
    static const char project_name[] = "ProjectName";
    return length == sizeof(project_name) - 1 &&
           memcmp(name, project_name, length) == 0;
}

/* Resolves the value a scalar Fn::Sub template emits. Only the ${ProjectName}
 * pseudo-parameter is knowable statically; any other ${...} variable makes the
 * emitted name unknowable, so it is left unresolved and the caller's
 * fail-closed path rejects it (D23). */
static int resolve_scalar_sub(const char *text, char *out, size_t capacity) {
    char template_text[512];
    raw_unquote(text, template_text, sizeof(template_text));
    static const char project_reference[] = "${ProjectName}";
    size_t used = 0;
    const char *cursor = template_text;
    while (*cursor != '\0') {
        if (cursor[0] == '$' && cursor[1] == '{') {
            const char *close = strchr(cursor + 2, '}');
            if (close == NULL ||
                !sub_variable_is_known(cursor + 2,
                                       (size_t)(close - (cursor + 2)))) {
                return 0;
            }
            size_t reference_length = sizeof(project_reference) - 1;
            if (used + reference_length + 1 > capacity) {
                return 0;
            }
            memcpy(out + used, project_reference, reference_length);
            used += reference_length;
            cursor = close + 1;
            continue;
        }
        if (used + 2 > capacity) {
            return 0;
        }
        out[used++] = *cursor++;
    }
    while (used > 0 && (out[used - 1] == ' ' || out[used - 1] == '\t')) {
        used--;
    }
    out[used] = '\0';
    return 1;
}

/* `!Join ['-', [!Ref ProjectName, 'ci']]` written as a scalar token. Resolving
 * it exactly keeps a short-form join from silently evading identity matching;
 * any unexpected shape is left unresolved. */
static int resolve_scalar_join(const char *text, char *out, size_t capacity) {
    const char *cursor = skip_name_spaces(text);
    if (*cursor != '[') {
        return 0;
    }
    cursor = skip_name_spaces(cursor + 1);
    const char *comma = strchr(cursor, ',');
    if (comma == NULL) {
        return 0;
    }
    char delimiter[32];
    char raw_delimiter[32];
    size_t delimiter_length = (size_t)(comma - cursor);
    if (delimiter_length >= sizeof(raw_delimiter)) {
        return 0;
    }
    memcpy(raw_delimiter, cursor, delimiter_length);
    raw_delimiter[delimiter_length] = '\0';
    if (!resolve_name_piece(raw_delimiter, delimiter, sizeof(delimiter))) {
        return 0;
    }
    cursor = skip_name_spaces(comma + 1);
    if (*cursor != '[') {
        return 0;
    }
    cursor++;
    size_t used = 0;
    out[0] = '\0';
    int first = 1;
    for (;;) {
        cursor = skip_name_spaces(cursor);
        if (*cursor == ']') {
            break;
        }
        const char *end = cursor;
        int quote = 0;
        while (*end != '\0') {
            char c = *end;
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                }
                end++;
                continue;
            }
            if (c == '\'' || c == '"') {
                quote = c;
                end++;
                continue;
            }
            if (c == ',' || c == ']') {
                break;
            }
            end++;
        }
        if (*end == '\0') {
            return 0;
        }
        char raw_piece[512];
        size_t piece_length = (size_t)(end - cursor);
        if (piece_length >= sizeof(raw_piece)) {
            return 0;
        }
        memcpy(raw_piece, cursor, piece_length);
        raw_piece[piece_length] = '\0';
        char piece[512];
        if (!resolve_name_piece(raw_piece, piece, sizeof(piece))) {
            return 0;
        }
        size_t piece_size = strlen(piece);
        size_t delim_size = first ? 0 : strlen(delimiter);
        if (used + delim_size + piece_size + 1 > capacity) {
            return 0;
        }
        if (delim_size > 0) {
            memcpy(out + used, delimiter, delim_size);
            used += delim_size;
        }
        memcpy(out + used, piece, piece_size);
        used += piece_size;
        out[used] = '\0';
        first = 0;
        cursor = end;
        if (*cursor == ',') {
            cursor++;
        }
    }
    /* The scalar carries the items list close bracket and then the join
     * argument-list close bracket; both must be consumed for the shape to be
     * the well-formed `['-', [items]]` form. */
    if (*cursor != ']') {
        return 0;
    }
    cursor = skip_name_spaces(cursor + 1);
    if (*cursor != ']') {
        return 0;
    }
    cursor = skip_name_spaces(cursor + 1);
    return *cursor == '\0';
}

/* Resolves a name node to the literal it emits. Returns 0 when the shape
 * cannot be resolved (e.g. a Ref to a resource or a substitution map). */
static int resolve_emitted_name(const node *name, char *out, size_t capacity) {
    out[0] = '\0';
    if (name == NULL) {
        return 0;
    }
    if (name->kind == NODE_MAP) {
        const node *fn_sub = map_get(name, "Fn::Sub");
        if (fn_sub != NULL) {
            if (fn_sub->kind == NODE_SCALAR) {
                return resolve_scalar_sub(fn_sub->text, out, capacity);
            }
            if (fn_sub->kind == NODE_SEQ && fn_sub->nitems == 1 &&
                fn_sub->items[0]->kind == NODE_SCALAR) {
                return resolve_scalar_sub(fn_sub->items[0]->text, out, capacity);
            }
            return 0;
        }
        const node *fn_join = map_get(name, "Fn::Join");
        if (fn_join != NULL) {
            if (fn_join->kind != NODE_SEQ || fn_join->nitems != 2 ||
                fn_join->items[0]->kind != NODE_SCALAR ||
                fn_join->items[1]->kind != NODE_SEQ) {
                return 0;
            }
            char delimiter[32];
            if (!resolve_name_piece(fn_join->items[0]->text, delimiter,
                                    sizeof(delimiter))) {
                return 0;
            }
            const node *parts = fn_join->items[1];
            size_t used = 0;
            out[0] = '\0';
            for (size_t i = 0; i < parts->nitems; i++) {
                char piece[512];
                if (!resolve_emitted_name(parts->items[i], piece, sizeof(piece))) {
                    return 0;
                }
                size_t piece_size = strlen(piece);
                size_t delim_size = i == 0 ? 0 : strlen(delimiter);
                if (used + delim_size + piece_size + 1 > capacity) {
                    return 0;
                }
                if (delim_size > 0) {
                    memcpy(out + used, delimiter, delim_size);
                    used += delim_size;
                }
                memcpy(out + used, piece, piece_size);
                used += piece_size;
                out[used] = '\0';
            }
            return 1;
        }
        const node *ref = map_get(name, "Ref");
        if (ref != NULL && node_scalar_equals(ref, "ProjectName")) {
            snprintf(out, capacity, "${ProjectName}");
            return 1;
        }
        return 0;
    }
    if (name->kind != NODE_SCALAR || name->text == NULL) {
        return 0;
    }
    const char *text = skip_name_spaces(name->text);
    if (strncmp(text, "!Sub", 4) == 0 && (text[4] == ' ' || text[4] == '\t')) {
        const char *body = skip_name_spaces(text + 4);
        /* The sequence form `!Sub [template, {map}]` can rebind the variables
         * that make up the name, so its emitted value is not knowable here. */
        if (*body == '[') {
            return 0;
        }
        return resolve_scalar_sub(body, out, capacity);
    }
    if (strncmp(text, "!Join", 5) == 0 && (text[5] == ' ' || text[5] == '\t')) {
        return resolve_scalar_join(text + 5, out, capacity);
    }
    if (strncmp(text, "!Ref", 4) == 0 && (text[4] == ' ' || text[4] == '\t')) {
        return resolve_name_piece(text, out, capacity);
    }
    if (text[0] == '!') {
        return 0;
    }
    raw_unquote(text, out, capacity);
    return 1;
}

static void ci_identities_add(ci_identities *set, const char *logical_id,
                              const char *name_field, const char *emitted) {
    if (set->count >= CI_IDENTITY_MAX) {
        set->overflowed++;
        return;
    }
    ci_identity *identity = &set->items[set->count++];
    identity->logical_id = logical_id;
    identity->name_field = name_field;
    snprintf(identity->name, sizeof(identity->name), "%s", emitted);
    identity->has_name = identity->name[0] != '\0';
}

static ci_identities find_ci_identities(const node *root) {
    ci_identities set = {0};
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return set;
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *resource = resources->pairs[i].value;
        const char *field = ci_identity_name_field(resource);
        if (field == NULL) {
            continue;
        }
        const node *name = map_get(map_get(resource, "Properties"), field);
        char emitted[256];
        if (!resolve_emitted_name(name, emitted, sizeof(emitted))) {
            /* An unnamed identity is auto-generated and can never equal the
             * project-scoped CI name; only a declared-but-unresolvable name
             * could be the CI identity. */
            if (name != NULL) {
                if (set.unresolved_names == 0) {
                    set.unresolved_name_id = resources->pairs[i].key;
                }
                set.unresolved_names++;
            }
            continue;
        }
        /* Exact normalized equality: a name that merely contains `-ci`
         * (e.g. `${ProjectName}-ci-tools`) is a different identity. */
        if (strcmp(emitted, CI_IDENTITY_NAME) != 0) {
            continue;
        }
        ci_identities_add(&set, resources->pairs[i].key, field, emitted);
    }
    return set;
}

static int entry_ref_target(const node *entry, char *out, size_t capacity) {
    if (entry == NULL) {
        return 0;
    }
    if (entry->kind == NODE_MAP) {
        const node *ref = map_get(entry, "Ref");
        if (ref == NULL || ref->kind != NODE_SCALAR) {
            return 0;
        }
        raw_unquote(ref->text, out, capacity);
        return 1;
    }
    if (entry->kind != NODE_SCALAR || entry->text == NULL) {
        return 0;
    }
    const char *text = skip_name_spaces(entry->text);
    if (strncmp(text, "!Ref", 4) != 0 || (text[4] != ' ' && text[4] != '\t')) {
        return 0;
    }
    text = skip_name_spaces(text + 4);
    snprintf(out, capacity, "%s", text);
    return 1;
}

static int entry_names_ci_identity(const node *entry, const ci_identities *set) {
    char target[256];
    if (entry_ref_target(entry, target, sizeof(target))) {
        for (size_t i = 0; i < set->count; i++) {
            if (set->items[i].logical_id != NULL &&
                strcmp(set->items[i].logical_id, target) == 0) {
                return 1;
            }
        }
    }
    char emitted[256];
    if (!resolve_emitted_name(entry, emitted, sizeof(emitted))) {
        return 0;
    }
    for (size_t i = 0; i < set->count; i++) {
        if (set->items[i].has_name && strcmp(set->items[i].name, emitted) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Membership and attachment sections must be plain lists. An intrinsic map
 * (long-form `Ref`, `Fn::If`, `Fn::ImportValue`, ...) or a bare scalar
 * intrinsic hides the principals or groups from the checker, so it fails
 * closed instead of being silently skipped (D27). */
static int section_is_plain_sequence(checker *c, const node *section,
                                     const char *what) {
    if (section == NULL || section->kind == NODE_SEQ) {
        return 1;
    }
    violation(c, "%s must be a plain list of statically resolvable entries; "
                 "intrinsic or mapping forms cannot be checked",
              what);
    return 0;
}

/* An entry is statically resolvable when it names a concrete principal: a
 * literal, a short- or long-form Ref to an existing logical id, a known !Sub,
 * or an exactly-resolvable !Join. An intrinsic map (Fn::If, Fn::ImportValue,
 * a substitution-map !Sub) or a nested list hides the principal from the
 * checker, so it fails closed instead of being treated as "not CI" (D29). */
static int entry_is_statically_resolvable(const node *entry,
                                          const node *resources) {
    if (entry == NULL || entry->kind == NODE_SEQ) {
        return 0;
    }
    char target[256];
    if (entry_ref_target(entry, target, sizeof(target))) {
        return resources == NULL || map_get(resources, target) != NULL;
    }
    /* The parser keeps a YAML flow collection written as a sequence item
     * (`- [a, b]`) as a scalar token; it is a nested list, not a name. */
    if (entry->kind == NODE_SCALAR && entry->text != NULL) {
        const char *text = skip_name_spaces(entry->text);
        if (*text == '[' || *text == '{') {
            return 0;
        }
    }
    char emitted[256];
    return resolve_emitted_name(entry, emitted, sizeof(emitted));
}

static int section_entries_are_statically_resolvable(checker *c,
                                                     const node *section,
                                                     const node *resources,
                                                     const char *what) {
    if (section == NULL || section->kind != NODE_SEQ) {
        return 1;
    }
    int all_resolvable = 1;
    for (size_t i = 0; i < section->nitems; i++) {
        if (entry_is_statically_resolvable(section->items[i], resources)) {
            continue;
        }
        violation(c, "%s entry must be statically resolvable (literal, !Ref of "
                     "an existing logical id, known-!Sub, or "
                     "exactly-resolvable !Join); intrinsic or nested forms "
                     "cannot be checked",
                  what);
        all_resolvable = 0;
    }
    return all_resolvable;
}

static int section_names_ci_identity(const node *section, const ci_identities *set) {
    for (size_t i = 0; i < scalar_count(section); i++) {
        if (entry_names_ci_identity(scalar_at(section, i), set)) {
            return 1;
        }
    }
    return 0;
}

/* Resolves a Groups/GroupName entry to the logical id of an existing Group
 * resource. The entry may be `!Ref <logical id>` or a literal/emitted name
 * that matches the Group's own GroupName. */
static int resolve_group_logical_id(const node *resources, const node *entry,
                                    char *out, size_t capacity) {
    if (entry == NULL) {
        return 0;
    }
    char ref[256];
    if (entry_ref_target(entry, ref, sizeof(ref))) {
        const node *group = map_get(resources, ref);
        if (group == NULL || !resource_is_type(group, "AWS::IAM::Group")) {
            return 0;
        }
        snprintf(out, capacity, "%s", ref);
        return 1;
    }
    char emitted[256];
    if (!resolve_emitted_name(entry, emitted, sizeof(emitted))) {
        return 0;
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *group = resources->pairs[i].value;
        if (!resource_is_type(group, "AWS::IAM::Group")) {
            continue;
        }
        char group_name[256];
        if (!resolve_emitted_name(map_get(map_get(group, "Properties"), "GroupName"),
                                  group_name, sizeof(group_name))) {
            continue;
        }
        if (strcmp(group_name, emitted) == 0) {
            snprintf(out, capacity, "%s", resources->pairs[i].key);
            return 1;
        }
    }
    return 0;
}

static void add_membership_group(ci_identities *set, const node *resources,
                                 const char *logical_id) {
    for (size_t i = 0; i < set->count; i++) {
        if (set->items[i].logical_id != NULL &&
            strcmp(set->items[i].logical_id, logical_id) == 0) {
            return;
        }
    }
    const node *group = map_get(resources, logical_id);
    char emitted[256];
    if (!resolve_emitted_name(map_get(map_get(group, "Properties"), "GroupName"),
                              emitted, sizeof(emitted))) {
        emitted[0] = '\0';
    }
    ci_identities_add(set, logical_id, "GroupName", emitted);
}

/* A CI user added to a group inherits the group's policies, so that group is
 * as much a CI-reader identity as a CI-named group. Membership is modelled
 * from both `AWS::IAM::UserToGroupAddition` and the user's own Groups list. */
static void add_ci_membership_groups(ci_identities *set, checker *c,
                                     const node *root) {
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return;
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *addition = resources->pairs[i].value;
        if (!resource_is_type(addition, "AWS::IAM::UserToGroupAddition")) {
            continue;
        }
        const node *properties = map_get(addition, "Properties");
        const node *users = map_get(properties, "Users");
        if (!section_is_plain_sequence(
                c, users, "UserToGroupAddition Properties.Users")) {
            continue;
        }
        section_entries_are_statically_resolvable(
            c, users, resources, "UserToGroupAddition Properties.Users");
        if (!section_names_ci_identity(users, set)) {
            continue;
        }
        char group_id[256];
        if (!resolve_group_logical_id(resources, map_get(properties, "GroupName"),
                                      group_id, sizeof(group_id))) {
            violation(c, "IAM membership entry must be statically resolvable "
                         "to a Group resource (literal name or !Ref of a "
                         "Group); cannot prove which policies attach");
            continue;
        }
        add_membership_group(set, resources, group_id);
    }
    /* Only memberships of a CI *user* make the joined group part of the CI
     * identity set; capture the user count before groups are appended. */
    const size_t ci_user_count = set->count;
    for (size_t i = 0; i < ci_user_count; i++) {
        const node *user = map_get(resources, set->items[i].logical_id);
        if (user == NULL || !resource_is_type(user, "AWS::IAM::User")) {
            continue;
        }
        const node *groups = map_get(map_get(user, "Properties"), "Groups");
        if (!section_is_plain_sequence(
                c, groups, "IAM membership Properties.Groups")) {
            continue;
        }
        section_entries_are_statically_resolvable(
            c, groups, resources, "IAM membership Properties.Groups");
        for (size_t j = 0; j < scalar_count(groups); j++) {
            char group_id[256];
            if (!resolve_group_logical_id(resources, scalar_at(groups, j),
                                          group_id, sizeof(group_id))) {
                violation(c, "IAM membership entry must be statically "
                             "resolvable to a Group resource (literal name or "
                             "!Ref of a Group); cannot prove which policies "
                             "attach");
                continue;
            }
            add_membership_group(set, resources, group_id);
        }
    }
}

static int policy_names_ci_identity(const node *policy, const ci_identities *set) {
    static const char *const sections[] = {"Users", "Roles", "Groups"};
    const node *properties = map_get(policy, "Properties");
    for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
        if (section_names_ci_identity(map_get(properties, sections[i]), set)) {
            return 1;
        }
    }
    return 0;
}

static int is_ci_reader_policy(const node *root, const node *policy,
                               const char *logical_id, const ci_identities *set) {
    if (!resource_is_type(policy, "AWS::IAM::ManagedPolicy") &&
        !resource_is_type(policy, "AWS::IAM::Policy")) {
        return 0;
    }
    const node *resources = template_resources(root);
    for (size_t i = 0; i < set->count; i++) {
        const node *identity = map_get(resources, set->items[i].logical_id);
        const node *arns = map_get(map_get(identity, "Properties"),
                                   "ManagedPolicyArns");
        if (arns != NULL && node_references(arns, logical_id)) {
            return 1;
        }
    }
    return policy_names_ci_identity(policy, set);
}

/* CI identities carry inline Policies directly on the user/role/group. Those
 * documents grant the same S3 access and are held to rule 4. A conditional or
 * otherwise non-literal entry is rejected rather than skipped. */
static void check_ci_inline_policies(checker *c, const node *resources,
                                     const ci_identities *set) {
    for (size_t i = 0; i < set->count; i++) {
        const node *identity = map_get(resources, set->items[i].logical_id);
        const node *policies =
            map_get(map_get(identity, "Properties"), "Policies");
        if (policies == NULL) {
            continue;
        }
        if (policies->kind != NODE_SEQ) {
            violation(c, "CI identity inline Policies must be a list of literal "
                         "PolicyDocument entries");
            continue;
        }
        for (size_t j = 0; j < policies->nitems; j++) {
            const node *document =
                map_get(policies->items[j], "PolicyDocument");
            if (document == NULL) {
                violation(c, "CI identity inline policy entry uses an unsupported "
                             "intrinsic shape");
                continue;
            }
            check_reader_statement(c, document);
        }
    }
}

/* A principal reference that cannot be tied to a User/Role/Group resource (a
 * parameter, an attribute, or an unsupported intrinsic) could name the CI
 * identity; failing closed keeps an unresolvable principal from escaping
 * rule 4. */
static void check_unresolved_policy_principals(checker *c, const node *root) {
    const node *resources = template_resources(root);
    static const char *const sections[] = {"Users", "Roles", "Groups"};
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *policy = resources->pairs[i].value;
        if (!resource_is_type(policy, "AWS::IAM::ManagedPolicy") &&
            !resource_is_type(policy, "AWS::IAM::Policy")) {
            continue;
        }
        const node *properties = map_get(policy, "Properties");
        for (size_t j = 0; j < sizeof(sections) / sizeof(sections[0]); j++) {
            const node *section = map_get(properties, sections[j]);
            char label[64];
            snprintf(label, sizeof(label), "IAM policy %s section", sections[j]);
            if (!section_is_plain_sequence(c, section, label)) {
                continue;
            }
            section_entries_are_statically_resolvable(c, section, resources,
                                                      label);
            for (size_t k = 0; k < scalar_count(section); k++) {
                const node *entry = scalar_at(section, k);
                char target[256];
                if (entry_ref_target(entry, target, sizeof(target))) {
                    const node *referenced = map_get(resources, target);
                    if (referenced != NULL &&
                        ci_identity_name_field(referenced) != NULL) {
                        continue;
                    }
                    violation(c, "IAM policy %s entry !Ref %s does not resolve "
                                 "to a User/Role/Group resource",
                              sections[j], target);
                    continue;
                }
                char emitted[256];
                if (!resolve_emitted_name(entry, emitted, sizeof(emitted))) {
                    violation(c, "IAM policy %s entry cannot be resolved to a "
                                 "principal name", sections[j]);
                }
            }
        }
    }
}

static void check_artifact_reader_policies(checker *c, const node *root) {
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return;
    }
    ci_identities identities = find_ci_identities(root);
    add_ci_membership_groups(&identities, c, root);
    if (identities.overflowed > 0) {
        violation(c, "too many CI identities to inspect (%zu not inspected)",
                  identities.overflowed);
    }
    if (identities.unresolved_names > 0) {
        violation(c, "IAM identity %s name must be statically resolvable "
                     "(literal or !Sub of known pseudo-parameters); cannot "
                     "prove it is not the CI identity",
                  identities.unresolved_name_id);
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const char *logical_id = resources->pairs[i].key;
        const node *policy = resources->pairs[i].value;
        const int canonical = strcmp(logical_id, "ArtifactReaderPolicy") == 0;
        if (!canonical && !is_ci_reader_policy(root, policy, logical_id, &identities)) {
            continue;
        }
        const node *properties = map_get(policy, "Properties");
        check_reader_statement(c, map_get(properties, "PolicyDocument"));
    }
    check_ci_inline_policies(c, resources, &identities);
    check_unresolved_policy_principals(c, root);
}

static int name_is_project_driven(const node *name) {
    return name != NULL &&
           (node_contains(name, "${ProjectName}") || node_references(name, "ProjectName"));
}

static int operator_policy_attached(const node *root, const char *user_id, const node *user) {
    const node *properties = map_get(user, "Properties");
    if (node_references(map_get(properties, "ManagedPolicyArns"), "OperatorPolicy")) {
        return 1;
    }
    const node *policy = map_get(template_resources(root), "OperatorPolicy");
    const node *policy_properties = map_get(policy, "Properties");
    return node_references(map_get(policy_properties, "Users"), user_id);
}

/*
 * The operator identity is the unconditional, project-named IAM user that
 * carries OperatorPolicy.  Locating it once keeps the user requirement and the
 * policy-union scans reading from the same definition.
 */
static const char *find_operator_user_name(const node *root) {
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return NULL;
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *user = resources->pairs[i].value;
        if (!resource_is_type(user, "AWS::IAM::User")) {
            continue;
        }
        if (map_get(user, "Condition") != NULL) {
            continue;
        }
        const node *properties = map_get(user, "Properties");
        if (!name_is_project_driven(map_get(properties, "UserName"))) {
            continue;
        }
        if (!operator_policy_attached(root, resources->pairs[i].key, user)) {
            continue;
        }
        return resources->pairs[i].key;
    }
    return NULL;
}

static const node *find_operator_user(const node *root) {
    const char *name = find_operator_user_name(root);
    if (name == NULL) {
        return NULL;
    }
    return map_get(template_resources(root), name);
}

/*
 * The operator permissions are split across several managed policies to stay
 * under the 6144-character AWS managed-policy quota.  Grant checks must reason
 * about the union attached to OperatorUser, not one policy resource, or a
 * statement moved to a sibling policy would silently escape validation.
 */
static void operator_policies_add(operator_policies *set, const node *policy,
                                  const char *attachment) {
    for (size_t i = 0; i < set->count; i++) {
        if (set->items[i] == policy) {
            return;
        }
    }
    if (set->count < OPERATOR_MAX_POLICIES) {
        set->items[set->count] = policy;
        set->attachments[set->count] = attachment;
        set->count++;
    } else {
        set->overflowed++;
    }
}

/* A policy attached to the operator user must be inspected regardless of the
 * resource type that carries it: ARM/IAM policy documents live on both
 * AWS::IAM::ManagedPolicy and AWS::IAM::Policy. */
static int is_operator_attach_policy(const node *resource) {
    return resource_is_type(resource, "AWS::IAM::ManagedPolicy") ||
           resource_is_type(resource, "AWS::IAM::Policy");
}

/* A ManagedPolicy may attach to the operator user without the user naming it
 * in ManagedPolicyArns: the policy's own Users/Roles/Groups list names the
 * user instead. Such a policy grants exactly the same permissions and must be
 * scanned by the same scope rules (CONTRACT checker rule 3). */
static const char *policy_attachment(const node *policy, const char *user_id) {
    static const char *const attachment_sections[] = {"Users", "Roles", "Groups"};
    const node *properties = map_get(policy, "Properties");
    for (size_t i = 0;
         i < sizeof(attachment_sections) / sizeof(attachment_sections[0]); i++) {
        if (node_references(map_get(properties, attachment_sections[i]), user_id)) {
            return attachment_sections[i];
        }
    }
    return NULL;
}

static operator_policies collect_operator_policies(const node *root) {
    operator_policies set = {0};
    const node *resources = template_resources(root);
    const char *user_id = find_operator_user_name(root);
    if (resources == NULL || resources->kind != NODE_MAP || user_id == NULL) {
        return set;
    }
    const node *user = map_get(resources, user_id);
    const node *arns = map_get(map_get(user, "Properties"), "ManagedPolicyArns");
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *candidate = resources->pairs[i].value;
        if (!is_operator_attach_policy(candidate)) {
            continue;
        }
        if (resource_is_type(candidate, "AWS::IAM::ManagedPolicy") && arns != NULL &&
            node_references(arns, resources->pairs[i].key)) {
            operator_policies_add(&set, candidate, NULL);
            continue;
        }
        const char *attachment = policy_attachment(candidate, user_id);
        if (attachment != NULL) {
            operator_policies_add(&set, candidate, attachment);
        }
    }
    return set;
}

static void check_operator_policy_overflow(checker *c, const operator_policies *set) {
    if (set->overflowed == 0) {
        return;
    }
    violation(c, "operator policy union exceeds the supported maximum of %d attached "
                 "policies (%zu not inspected)",
              OPERATOR_MAX_POLICIES, set->overflowed);
}

static const node *operator_policies_find_statement(const operator_policies *set,
                                                    const char *action) {
    for (size_t i = 0; i < set->count; i++) {
        const node *found = find_statement(set->items[i], action);
        if (found != NULL) {
            return found;
        }
    }
    return NULL;
}

/*
 * Spec §3: the operator stack always creates the human/operator IAM user
 * `<project>` (provision mints its key) and that user must carry the operator
 * managed policy.  The CI user is conditional; the operator user is not.
 */
static void check_operator_user(checker *c, const node *root) {
    if (find_operator_user(root) != NULL) {
        return;
    }
    violation(c, "operator stack must create an unconditional ProjectName-named IAM user "
                 "attached to OperatorPolicy");
}

static int statement_allows_service(const node *statement, const char *service) {
    if (statement == NULL || statement->kind != NODE_MAP) {
        return 0;
    }
    if (!action_list_contains(map_get(statement, "Action"), "sts:AssumeRole")) {
        return 0;
    }
    const node *services = map_get(map_get(statement, "Principal"), "Service");
    for (size_t i = 0; i < scalar_count(services); i++) {
        const node *entry = scalar_at(services, i);
        if (entry != NULL && node_scalar_equals(entry, service)) {
            return 1;
        }
    }
    return 0;
}

static int trust_allows_service(const node *statement, const char *service) {
    if (statement == NULL) {
        return 0;
    }
    if (statement->kind == NODE_SEQ) {
        for (size_t i = 0; i < statement->nitems; i++) {
            if (trust_allows_service(statement->items[i], service)) {
                return 1;
            }
        }
        return 0;
    }
    return statement_allows_service(statement, service);
}

/*
 * The Image Builder pipeline runs under a service execution role owned by the
 * operator stack.  That role must be assumable by imagebuilder.amazonaws.com
 * (an EC2 trust is silently unusable) and must be able to publish the baked
 * AMI id through the native distribution SsmParameterConfigurations.  Fail
 * closed when either half is missing.
 */
static void check_imagebuilder_execution_role(checker *c, const node *root) {
    if (map_get(template_parameters(root), "EnableImageBuilder") == NULL) {
        return;
    }
    const node *role = map_get(template_resources(root), "ImageBuilderExecutionRole");
    if (role == NULL) {
        violation(c, "missing ImageBuilderExecutionRole resource");
        return;
    }
    const node *properties = map_get(role, "Properties");
    const node *assume = map_get(properties, "AssumeRolePolicyDocument");
    const int trust_ok =
        trust_allows_service(map_get(assume, "Statement"), "imagebuilder.amazonaws.com");

    const node *publish = find_statement(role, "ssm:PutParameter");
    const int publish_ok =
        publish != NULL &&
        node_contains(map_get(publish, "Resource"), "${ProjectName}/ami/baked/");

    if (!trust_ok || !publish_ok) {
        violation(c, "ImageBuilderExecutionRole must trust imagebuilder.amazonaws.com "
                     "and grant ssm:PutParameter on ${ProjectName}/ami/baked/*");
    }
}

/*
 * A template that can create Image Builder resources must let the operator
 * identity create them too.  This is the gap class that let a first
 * ENABLE_IMAGE_BUILDER=true deploy reach AccessDenied on
 * imagebuilder:CreateDistributionConfiguration: the infra stack created the
 * resources while the operator policy granted zero imagebuilder actions.
 * Fail closed on the two core create actions so the permissions can never
 * drift out of the operator policy again.
 */
static void check_operator_image_builder_permissions(checker *c, const node *root) {
    if (map_get(template_parameters(root), "EnableImageBuilder") == NULL) {
        return;
    }
    const operator_policies operator = collect_operator_policies(root);
    if (operator.count == 0) {
        /* Missing operator user/policy is reported elsewhere. */
        return;
    }
    if (operator_policies_find_statement(&operator, "imagebuilder:CreateComponent") == NULL ||
        operator_policies_find_statement(&operator, "imagebuilder:CreateImagePipeline") == NULL ||
        operator_policies_find_statement(&operator, "imagebuilder:GetComponent") == NULL) {
        violation(c, "operator policies must grant imagebuilder:CreateComponent, "
                     "imagebuilder:CreateImagePipeline, and imagebuilder:GetComponent "
                     "when EnableImageBuilder is declared");
    }
}

/*
 * The infra stack always creates its artifact bucket (and conditionally the
 * cert bucket) through CloudFormation's S3 handlers, which run under the
 * caller's identity. Object-level release access is therefore insufficient:
 * the operator policy must also grant the complete bucket handler surface on
 * the artifacts bucket pattern, or a deploy rolls back mid-configure with an
 * AccessDenied. The IAM action names differ from the S3 API names for several
 * subresources (public access block, encryption, ownership controls); the list
 * below is the canonical set, enumerated and never wildcarded.
 */
static const char *const BUCKET_HANDLER_ACTIONS[] = {
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:GetBucketLocation",
    "s3:GetBucketAcl",
    "s3:GetBucketVersioning",
    "s3:PutBucketVersioning",
    "s3:GetBucketTagging",
    "s3:PutBucketTagging",
    "s3:GetBucketPublicAccessBlock",
    "s3:PutBucketPublicAccessBlock",
    "s3:GetEncryptionConfiguration",
    "s3:PutEncryptionConfiguration",
    "s3:DeleteBucketEncryption",
    "s3:GetBucketOwnershipControls",
    "s3:PutBucketOwnershipControls",
    "s3:GetLifecycleConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:DeleteBucketLifecycle",
    "s3:ListBucket",
};

/* CloudFormation EC2 handler surface for the VPC/subnet/IGW/route-table/
 * security-group resources the infra stack creates. Each action is anchored to
 * the VpcLifecycle statement (which also grants ec2:CreateVpc) so an unrelated
 * launch-time grant of the same action cannot satisfy the check. */
static const char *const INFRA_EC2_HANDLER_ACTIONS[] = {
    "ec2:CreateVpc",
    "ec2:DeleteVpc",
    "ec2:ModifyVpcAttribute",
    "ec2:CreateSubnet",
    "ec2:DeleteSubnet",
    "ec2:ModifySubnetAttribute",
    "ec2:CreateInternetGateway",
    "ec2:DeleteInternetGateway",
    "ec2:AttachInternetGateway",
    "ec2:DetachInternetGateway",
    "ec2:CreateRouteTable",
    "ec2:DeleteRouteTable",
    "ec2:CreateRoute",
    "ec2:DeleteRoute",
    "ec2:ReplaceRoute",
    "ec2:AssociateRouteTable",
    "ec2:DisassociateRouteTable",
    "ec2:ReplaceRouteTableAssociation",
    "ec2:CreateSecurityGroup",
    "ec2:DeleteSecurityGroup",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
    "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
    "ec2:CreateTags",
    "ec2:DeleteTags",
};

/* Spot alerts are optional in the infra stack but, when enabled, the SNS and
 * EventBridge handlers run as the same operator identity. */
static const char *const SPOT_ALERT_SNS_ACTIONS[] = {
    "sns:CreateTopic",
    "sns:DeleteTopic",
    "sns:GetTopicAttributes",
    "sns:Subscribe",
    "sns:Unsubscribe",
    "sns:GetSubscriptionAttributes",
    "sns:SetSubscriptionAttributes",
    "sns:ListSubscriptionsByTopic",
};

static const char *const SPOT_ALERT_EVENTS_ACTIONS[] = {
    "events:PutRule",
    "events:DeleteRule",
    "events:DescribeRule",
    "events:PutTargets",
    "events:RemoveTargets",
    "events:ListTargetsByRule",
};

static const node *find_statement_pair(const node *n, const char *action,
                                       const char *anchor) {
    if (n == NULL) {
        return NULL;
    }
    if (n->kind == NODE_MAP) {
        const node *actions = map_get(n, "Action");
        if (actions != NULL && action_list_contains(actions, action) &&
            action_list_contains(actions, anchor)) {
            return n;
        }
        for (size_t i = 0; i < n->npairs; i++) {
            const node *found = find_statement_pair(n->pairs[i].value, action, anchor);
            if (found != NULL) {
                return found;
            }
        }
    } else if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            const node *found = find_statement_pair(n->items[i], action, anchor);
            if (found != NULL) {
                return found;
            }
        }
    }
    return NULL;
}

static const node *find_statement_on_pattern(const node *n, const char *action,
                                             const char *needle) {
    if (n == NULL) {
        return NULL;
    }
    if (n->kind == NODE_MAP) {
        const node *actions = map_get(n, "Action");
        const node *resource = map_get(n, "Resource");
        if (actions != NULL && action_list_contains(actions, action) &&
            node_contains(resource, needle)) {
            return n;
        }
        for (size_t i = 0; i < n->npairs; i++) {
            const node *found = find_statement_on_pattern(n->pairs[i].value, action, needle);
            if (found != NULL) {
                return found;
            }
        }
    } else if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            const node *found = find_statement_on_pattern(n->items[i], action, needle);
            if (found != NULL) {
                return found;
            }
        }
    }
    return NULL;
}

static int operator_policies_grant_with_anchor(const operator_policies *set,
                                               const char *action, const char *anchor) {
    for (size_t i = 0; i < set->count; i++) {
        if (find_statement_pair(set->items[i], action, anchor) != NULL) {
            return 1;
        }
    }
    return 0;
}

static int operator_policies_grant_on_pattern(const operator_policies *set,
                                              const char *action, const char *needle) {
    for (size_t i = 0; i < set->count; i++) {
        if (find_statement_on_pattern(set->items[i], action, needle) != NULL) {
            return 1;
        }
    }
    return 0;
}

static void check_operator_bucket_lifecycle(checker *c, const node *root) {
    const operator_policies operator = collect_operator_policies(root);
    if (operator.count == 0) {
        /* Missing operator user/policy is reported elsewhere. */
        return;
    }
    const int cert_bucket = map_get(template_parameters(root), "CertBucketEnabled") != NULL;
    for (size_t i = 0;
         i < sizeof(BUCKET_HANDLER_ACTIONS) / sizeof(BUCKET_HANDLER_ACTIONS[0]); i++) {
        const char *action = BUCKET_HANDLER_ACTIONS[i];
        if (!operator_policies_grant_on_pattern(&operator, action,
                                                "${ProjectName}-artifacts-")) {
            violation(c, "operator policies must grant %s on the "
                         "${ProjectName}-artifacts- bucket pattern",
                      action);
        }
        if (cert_bucket &&
            !operator_policies_grant_on_pattern(&operator, action,
                                                "${ProjectName}-certs-")) {
            violation(c, "operator policies must grant %s on the "
                         "${ProjectName}-certs- bucket pattern",
                      action);
        }
    }
}

static void check_operator_infra_handler_permissions(checker *c, const node *root) {
    const operator_policies operator = collect_operator_policies(root);
    if (operator.count == 0) {
        return;
    }
    for (size_t i = 0;
         i < sizeof(INFRA_EC2_HANDLER_ACTIONS) / sizeof(INFRA_EC2_HANDLER_ACTIONS[0]); i++) {
        if (!operator_policies_grant_with_anchor(&operator, INFRA_EC2_HANDLER_ACTIONS[i],
                                                 "ec2:CreateVpc")) {
            violation(c, "operator policies must grant %s for the infra stack EC2 handlers",
                      INFRA_EC2_HANDLER_ACTIONS[i]);
        }
    }
    for (size_t i = 0;
         i < sizeof(SPOT_ALERT_SNS_ACTIONS) / sizeof(SPOT_ALERT_SNS_ACTIONS[0]); i++) {
        if (!operator_policies_grant_with_anchor(&operator, SPOT_ALERT_SNS_ACTIONS[i],
                                                 "sns:CreateTopic")) {
            violation(c, "operator policies must grant %s for the spot-alert SNS handlers",
                      SPOT_ALERT_SNS_ACTIONS[i]);
        }
    }
    for (size_t i = 0;
         i < sizeof(SPOT_ALERT_EVENTS_ACTIONS) / sizeof(SPOT_ALERT_EVENTS_ACTIONS[0]); i++) {
        if (!operator_policies_grant_with_anchor(&operator, SPOT_ALERT_EVENTS_ACTIONS[i],
                                                 "events:PutRule")) {
            violation(c, "operator policies must grant %s for the spot-alert EventBridge "
                         "handlers", SPOT_ALERT_EVENTS_ACTIONS[i]);
        }
    }
}

/* Operator INLINE policies live in the user's own Properties.Policies rather
 * than in a resource-level policy document; they grant the same S3 access and
 * are held to the same rule-1/rule-2 own-bucket scope. */
static void check_operator_inline_policies(checker *c, const node *root) {
    const node *user = find_operator_user(root);
    if (user == NULL) {
        return;
    }
    const node *policies = map_get(map_get(user, "Properties"), "Policies");
    if (policies == NULL) {
        return;
    }
    /* Inline policies are a literal list. A conditional element or an
     * intrinsic standing in for the list cannot be proven to stay in scope, so
     * it fails closed instead of being silently skipped. */
    if (policies->kind != NODE_SEQ) {
        violation(c, "operator inline Policies must be a literal list of "
                     "PolicyDocument entries");
        return;
    }
    for (size_t i = 0; i < policies->nitems; i++) {
        const node *document = map_get(policies->items[i], "PolicyDocument");
        if (document == NULL) {
            const node *fn_if = map_get(policies->items[i], "Fn::If");
            violation(c, "operator inline policy entry uses an unsupported "
                         "intrinsic shape%s",
                      fn_if != NULL ? " Fn::If" : "");
            continue;
        }
        check_operator_s3_scope(c, document, "Policies");
    }
}

static void check_operator(checker *c, const node *root) {
    check_required_params(c, root, OPERATOR_PARAMS,
                          sizeof(OPERATOR_PARAMS) / sizeof(OPERATOR_PARAMS[0]));
    check_required_outputs(c, root, OPERATOR_OUTPUTS,
                           sizeof(OPERATOR_OUTPUTS) / sizeof(OPERATOR_OUTPUTS[0]));
    check_no_exports(c, root);
    check_stack_name_contract(c, root);

    const node *resources = template_resources(root);
    check_iam_node(c, resources);
    check_required_actions(c, root, OPERATOR_ACTIONS,
                           sizeof(OPERATOR_ACTIONS) / sizeof(OPERATOR_ACTIONS[0]));

    const node *run = find_statement_with_condition(resources, "ec2:RunInstances",
                                                    "aws:TagKeys");
    if (run == NULL) {
        violation(c, "RunInstances is not tag-gated");
    } else {
        const node *condition = map_get(run, "Condition");
        /* ec2:CreateAction is absent while IAM evaluates RunInstances itself, so
         * gating the grant on it makes the statement never match. It belongs only
         * on the tag-on-create CreateTags statement below. */
        if (node_contains(condition, "ec2:CreateAction")) {
            violation(c, "RunInstances must not be gated by ec2:CreateAction");
        }
        if (!node_contains(condition, "ec2:InstanceType")) {
            violation(c, "RunInstances condition lacks the instance-type allowlist");
        }
        if (!node_contains(condition, "aws:RequestTag/Project")) {
            violation(c, "RunInstances condition lacks the Project request tag");
        }
    }

    if (find_statement_with_condition(resources, "ec2:TerminateInstances",
                                      "ec2:ResourceTag/Project") == NULL) {
        violation(c, "TerminateInstances is not tag-gated");
    }

    const node *create_tags = find_statement(resources, "ec2:CreateTags");
    if (create_tags == NULL) {
        violation(c, "CreateTags statement is missing");
    } else {
        const node *condition = map_get(create_tags, "Condition");
        if (condition == NULL || !node_contains(condition, "ec2:CreateAction")) {
            violation(c, "CreateTags is not gated by ec2:CreateAction");
        } else {
            /* ec2:CreateAction takes the bare API action name, not the
             * service-prefixed action. StringEquals is exact-match, so
             * "ec2:RunInstances" never matches and tag-on-create is denied. */
            const node *string_equals = map_get(condition, "StringEquals");
            const node *create_action = map_get(string_equals, "ec2:CreateAction");
            if (!node_scalar_equals(create_action, "RunInstances")) {
                violation(c, "CreateTags ec2:CreateAction must be the unprefixed action "
                             "name RunInstances");
            }
        }
        if (condition == NULL || !node_contains(condition, "aws:TagKeys")) {
            violation(c, "CreateTags is not gated by aws:TagKeys");
        }
        check_tag_key_allowlist(c, create_tags);
    }

    if (find_statement_with_condition(resources, "iam:PassRole",
                                      "iam:PassedToService") == NULL) {
        violation(c, "PassRole is not restricted to the EC2 service");
    }
    if (find_statement_with_condition(resources, "ec2:GetConsoleOutput",
                                      "ec2:ResourceTag/Project") == NULL) {
        violation(c, "GetConsoleOutput is not tag-gated");
    }

    check_operator_role_resources(c, root);
    check_operator_user(c, root);
    check_imagebuilder_execution_role(c, root);
    check_operator_image_builder_permissions(c, root);
    check_operator_bucket_lifecycle(c, root);
    check_operator_infra_handler_permissions(c, root);
    /* check_iam_node above already walks every resource node, so the generic
     * wildcard/action scan covers the managed-policy union attached to the
     * user. These scope checks reason about the same union explicitly. */
    const operator_policies operator = collect_operator_policies(root);
    check_operator_policy_overflow(c, &operator);
    for (size_t i = 0; i < operator.count; i++) {
        check_operator_s3_scope(c, operator.items[i], operator.attachments[i]);
    }
    check_operator_inline_policies(c, root);
    check_artifact_reader_policies(c, root);
}

/* ---------------------------------------------------------------- infra */

static const char *const INFRA_PARAMS[] = {
    "ProjectName",
    "ReleaseTag",
    "ReleaseManifestSha256",
    "OperatorCidr",
    "IngressTcp",
    "IngressUdp",
    "CertBucketEnabled",
};

static const char *const INFRA_OUTPUTS[] = {
    "VpcId",
    "SubnetId",
    "SecurityGroupId",
    "InstanceProfileName",
    "ArtifactBucketName",
    "CertBucketName",
    "DdnsHost",
};

static int resource_is_type(const node *resource, const char *type) {
    return node_scalar_equals(map_get(resource, "Type"), type);
}

static int property_is_true(const node *resource, const char *name) {
    const node *properties = map_get(resource, "Properties");
    return node_scalar_equals(map_get(properties, name), "true");
}

static void check_bucket(checker *c, const node *resource, const char *name) {
    if (!node_scalar_equals(map_get(resource, "DeletionPolicy"), "RetainExceptOnCreate")) {
        violation(c, "bucket %s must declare DeletionPolicy RetainExceptOnCreate", name);
    }
    if (!node_scalar_equals(map_get(resource, "UpdateReplacePolicy"), "Retain")) {
        violation(c, "bucket %s must declare UpdateReplacePolicy Retain", name);
    }

    const node *properties = map_get(resource, "Properties");
    const node *block = map_get(properties, "PublicAccessBlockConfiguration");
    static const char *const block_keys[] = {
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
    };
    for (size_t i = 0; i < sizeof(block_keys) / sizeof(block_keys[0]); i++) {
        if (!node_scalar_equals(map_get(block, block_keys[i]), "true")) {
            violation(c, "bucket %s must enable public access block %s", name, block_keys[i]);
        }
    }

    const node *encryption = map_get(properties, "BucketEncryption");
    const node *configuration = map_get(encryption, "ServerSideEncryptionConfiguration");
    if (configuration == NULL || configuration->kind != NODE_SEQ ||
        configuration->nitems == 0) {
        violation(c, "bucket %s must declare SSE-S3 encryption", name);
    } else {
        const node *defaults = map_get(configuration->items[0],
                                       "ServerSideEncryptionByDefault");
        if (!node_scalar_equals(map_get(defaults, "SSEAlgorithm"), "AES256")) {
            violation(c, "bucket %s must use SSE-S3 (AES256)", name);
        }
    }

    const node *versioning = map_get(properties, "VersioningConfiguration");
    if (!node_scalar_equals(map_get(versioning, "Status"), "Suspended")) {
        violation(c, "bucket %s must disable versioning", name);
    }

    const node *lifecycle = map_get(properties, "LifecycleConfiguration");
    if (lifecycle != NULL && node_contains(lifecycle, "Expiration")) {
        violation(c, "bucket %s must not expire objects via lifecycle", name);
    }
}

static int egress_is_open(const node *security_group) {
    const node *properties = map_get(security_group, "Properties");
    const node *egress = map_get(properties, "SecurityGroupEgress");
    for (size_t i = 0; i < scalar_count(egress); i++) {
        const node *rule = scalar_at(egress, i);
        if (rule == NULL || rule->kind != NODE_MAP) {
            continue;
        }
        if (node_scalar_equals(map_get(rule, "IpProtocol"), "-1") &&
            node_scalar_equals(map_get(rule, "CidrIp"), "0.0.0.0/0")) {
            return 1;
        }
    }
    return 0;
}

static int ssh_ingress_is_conditional(const node *root) {
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return 0;
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *resource = resources->pairs[i].value;
        if (!resource_is_type(resource, "AWS::EC2::SecurityGroupIngress")) {
            continue;
        }
        const node *properties = map_get(resource, "Properties");
        if (node_scalar_equals(map_get(properties, "FromPort"), "22") &&
            node_scalar_equals(map_get(resource, "Condition"), "HasOperatorCidr")) {
            return 1;
        }
    }
    return 0;
}

static void check_image_builder_references(checker *c, const node *root) {
    const node *params = template_parameters(root);
    if (params == NULL || params->kind != NODE_MAP) {
        return;
    }
    for (size_t i = 0; i < params->npairs; i++) {
        const char *name = params->pairs[i].key;
        if (strncmp(name, "AmiId", 5) == 0 && !node_references(root, name)) {
            violation(c, "AMI parameter %s is present but never referenced", name);
        }
    }
}

static const char *skip_spaces(const char *text) {
    while (*text == ' ' || *text == '\t') {
        text++;
    }
    return text;
}

/* The parser keeps short-form intrinsics as opaque scalars, so a pinned binding
 * is recognised textually: the parameter reference must follow an
 * `!If [AmiPinned, ...]` condition within the same binding. */
static int scalar_refs_under_pinned(const char *text, const char *name) {
    char reference[256];
    int written = snprintf(reference, sizeof(reference), "!Ref %s", name);
    if (written < 0 || (size_t)written >= sizeof(reference)) {
        return 0;
    }
    const char *ref_at = strstr(text, reference);
    if (ref_at == NULL) {
        return 0;
    }
    for (const char *if_at = text; (if_at = strstr(if_at, "!If")) != NULL; if_at++) {
        if (if_at > ref_at) {
            break;
        }
        const char *probe = skip_spaces(if_at + 3);
        if (*probe != '[') {
            continue;
        }
        probe = skip_spaces(probe + 1);
        if (strncmp(probe, "AmiPinned", 9) != 0) {
            continue;
        }
        probe = skip_spaces(probe + 9);
        if (*probe == ',' && probe < ref_at) {
            return 1;
        }
    }
    return 0;
}

/* Long-form `Fn::If: [AmiPinned, ...]` is structural in the parser, so match it
 * directly rather than through the scalar text. */
static int fn_if_refs_under_pinned(const node *map, const char *name) {
    const node *fn_if = map_get(map, "Fn::If");
    if (fn_if == NULL || fn_if->kind != NODE_SEQ || fn_if->nitems < 2) {
        return 0;
    }
    if (!node_scalar_equals(fn_if->items[0], "AmiPinned")) {
        return 0;
    }
    for (size_t i = 1; i < fn_if->nitems; i++) {
        if (node_references(fn_if->items[i], name)) {
            return 1;
        }
    }
    return 0;
}

static int node_refs_under_pinned(const node *n, const char *name) {
    if (n == NULL) {
        return 0;
    }
    if (n->kind == NODE_SCALAR) {
        return scalar_refs_under_pinned(n->text, name);
    }
    if (n->kind == NODE_MAP) {
        if (fn_if_refs_under_pinned(n, name)) {
            return 1;
        }
        for (size_t i = 0; i < n->npairs; i++) {
            if (node_refs_under_pinned(n->pairs[i].value, name)) {
                return 1;
            }
        }
        return 0;
    }
    for (size_t i = 0; i < n->nitems; i++) {
        if (node_refs_under_pinned(n->items[i], name)) {
            return 1;
        }
    }
    return 0;
}

/* A pinned AMI override is all-or-nothing at the template level: the arch
 * parameters are either both absent or both declared and both bound under the
 * AmiPinned condition. Per-declared-arch requiredness stays with the runtime
 * config matrix. */
static void check_ami_id_arch_symmetry(checker *c, const node *root) {
    static const char *const arch_parameters[] = {
        "AmiIdAmd64",
        "AmiIdArm64",
    };
    const size_t arch_count = sizeof(arch_parameters) / sizeof(arch_parameters[0]);

    const node *parameters = template_parameters(root);
    if (parameters == NULL || parameters->kind != NODE_MAP) {
        return;
    }

    int declared = 0;
    for (size_t i = 0; i < arch_count; i++) {
        if (map_get(parameters, arch_parameters[i]) != NULL) {
            declared++;
        }
    }
    if (declared == 0) {
        return;
    }

    for (size_t i = 0; i < arch_count; i++) {
        const char *name = arch_parameters[i];
        if (map_get(parameters, name) == NULL) {
            violation(c, "pinned AMI override must declare parameter %s", name);
            continue;
        }
        if (!node_refs_under_pinned(root, name)) {
            violation(c, "AMI parameter %s must be referenced under the AmiPinned condition",
                      name);
        }
    }
}

#define INGRESS_SLOTS 8

static void check_app_ingress_rule(checker *c, const node *root, const char *resource_name,
                                   const char *port_parameter, const char *cidr_parameter,
                                   const char *condition_name) {
    const node *resources = template_resources(root);
    const node *parameters = template_parameters(root);
    if (map_get(parameters, port_parameter) == NULL) {
        violation(c, "missing ingress parameter %s", port_parameter);
    }
    if (map_get(parameters, cidr_parameter) == NULL) {
        violation(c, "missing ingress parameter %s", cidr_parameter);
    }

    const node *rule = map_get(resources, resource_name);
    if (rule == NULL) {
        violation(c, "missing app ingress rule %s", resource_name);
        return;
    }
    const node *properties = map_get(rule, "Properties");
    char expected[128];
    snprintf(expected, sizeof(expected), "!Ref %s", port_parameter);
    if (!node_scalar_equals(map_get(properties, "FromPort"), expected) ||
        !node_scalar_equals(map_get(properties, "ToPort"), expected)) {
        violation(c, "ingress rule %s must open its own configured port %s", resource_name,
                  port_parameter);
    }
    snprintf(expected, sizeof(expected), "!Ref %s", cidr_parameter);
    if (!node_scalar_equals(map_get(properties, "CidrIp"), expected)) {
        violation(c, "ingress rule %s must use its configured CIDR %s", resource_name,
                  cidr_parameter);
    }
    if (!node_scalar_equals(map_get(rule, "Condition"), condition_name)) {
        violation(c, "ingress rule %s must be conditional on %s", resource_name,
                  condition_name);
    }
}

static void check_app_ingress(checker *c, const node *root) {
    for (int i = 0; i < INGRESS_SLOTS; i++) {
        char resource_name[32];
        char port_parameter[32];
        char cidr_parameter[32];
        char condition_name[32];

        snprintf(resource_name, sizeof(resource_name), "TcpIngress%d", i);
        snprintf(port_parameter, sizeof(port_parameter), "IngressTcpPort%d", i);
        snprintf(cidr_parameter, sizeof(cidr_parameter), "IngressTcpCidr%d", i);
        snprintf(condition_name, sizeof(condition_name), "HasIngressTcp%d", i);
        check_app_ingress_rule(c, root, resource_name, port_parameter, cidr_parameter,
                               condition_name);

        snprintf(resource_name, sizeof(resource_name), "UdpIngress%d", i);
        snprintf(port_parameter, sizeof(port_parameter), "IngressUdpPort%d", i);
        snprintf(cidr_parameter, sizeof(cidr_parameter), "IngressUdpCidr%d", i);
        snprintf(condition_name, sizeof(condition_name), "HasIngressUdp%d", i);
        check_app_ingress_rule(c, root, resource_name, port_parameter, cidr_parameter,
                               condition_name);
    }

    /* No ingress rule may hardcode the world CIDR: configured CIDRs are
     * parameterised and the only 0.0.0.0/0 value is a documented caller
     * default carried in the parameter, never baked into the template. */
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return;
    }
    for (size_t i = 0; i < resources->npairs; i++) {
        const node *resource = resources->pairs[i].value;
        if (!resource_is_type(resource, "AWS::EC2::SecurityGroupIngress")) {
            continue;
        }
        const node *properties = map_get(resource, "Properties");
        if (node_scalar_equals(map_get(properties, "CidrIp"), "0.0.0.0/0")) {
            violation(c, "ingress rule %s hardcodes the world CIDR", resources->pairs[i].key);
        }
    }
}

/*
 * The baked AMI pipeline publishes the output image natively: the distribution
 * must name AMIs with the Image Builder buildDate token (the service rejects
 * buildVersion) and carry SsmParameterConfigurations so Image Builder writes
 * the AMI id to /<project>/ami/baked/latest during distribution.  The pipeline
 * must also set its ExecutionRole, without which it never runs.  Each missing
 * clause is its own violation.
 */
static void check_baked_distribution_publish(checker *c, const node *root) {
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        return;
    }

    /* The recipe must hand the parent image to Image Builder verbatim: a raw
     * AMI id or a full SSM parameter ARN. Synthesizing an SSM ARN from a bare
     * path (or baking a literal instead of the parameter) produces an invalid
     * ParentImage, so accept only `!Ref ImageBuilderParentImage`. */
    const node *recipe = map_get(resources, "BakedImageRecipe");
    if (recipe == NULL) {
        violation(c, "BakedImageRecipe must be declared");
    } else {
        const node *parent =
            map_get(map_get(recipe, "Properties"), "ParentImage");
        /* Short-form intrinsics parse as opaque scalars, so a verbatim Ref is
         * exactly this string. Fn::Sub and literals fail that equality. */
        int plain_ref =
            node_scalar_equals(parent, "!Ref ImageBuilderParentImage");
        if (!plain_ref) {
            violation(c, "BakedImageRecipe ParentImage must be "
                         "!Ref ImageBuilderParentImage (no Fn::Sub or literal)");
        }
    }

    const node *distribution = NULL;
    for (size_t i = 0; i < resources->npairs; i++) {
        if (resource_is_type(resources->pairs[i].value,
                             "AWS::ImageBuilder::DistributionConfiguration")) {
            distribution = resources->pairs[i].value;
            break;
        }
    }
    if (distribution == NULL) {
        return;
    }
    const node *properties = map_get(distribution, "Properties");
    const node *distributions = map_get(properties, "Distributions");
    const node *entry = scalar_at(distributions, 0);
    if (entry == NULL || entry->kind != NODE_MAP) {
        violation(c, "baked distribution must declare a Distributions entry");
        return;
    }
    const node *ami = map_get(entry, "AmiDistributionConfiguration");
    if (!node_contains(map_get(ami, "Name"), "{{ imagebuilder:buildDate }}")) {
        violation(c, "baked AMI distribution Name must contain {{ imagebuilder:buildDate }}");
    }
    const node *ssm = map_get(entry, "SsmParameterConfigurations");
    int publish_ok = 0;
    for (size_t i = 0; i < scalar_count(ssm); i++) {
        const node *config = scalar_at(ssm, i);
        if (config != NULL && config->kind == NODE_MAP &&
            node_contains(map_get(config, "ParameterName"),
                          "/${ProjectName}/ami/baked/")) {
            publish_ok = 1;
        }
    }
    if (!publish_ok) {
        violation(c, "baked distribution must publish to /${ProjectName}/ami/baked/ "
                     "via SsmParameterConfigurations");
    }
    const node *pipeline = map_get(resources, "BakedImagePipeline");
    if (pipeline == NULL || map_get(map_get(pipeline, "Properties"), "ExecutionRole") == NULL) {
        violation(c, "BakedImagePipeline must set ExecutionRole");
    }
}

static void check_infra(checker *c, const node *root) {
    check_required_params(c, root, INFRA_PARAMS,
                          sizeof(INFRA_PARAMS) / sizeof(INFRA_PARAMS[0]));
    check_required_outputs(c, root, INFRA_OUTPUTS,
                           sizeof(INFRA_OUTPUTS) / sizeof(INFRA_OUTPUTS[0]));
    check_no_exports(c, root);
    check_stack_name_contract(c, root);
    check_image_builder_references(c, root);
    check_ami_id_arch_symmetry(c, root);
    check_baked_distribution_publish(c, root);

    const node *resources = template_resources(root);
    check_iam_node(c, resources);
    check_app_ingress(c, root);

    int have_vpc = 0;
    int have_subnet = 0;
    int have_security_group = 0;
    int have_bucket = 0;

    if (resources != NULL && resources->kind == NODE_MAP) {
        for (size_t i = 0; i < resources->npairs; i++) {
            const char *name = resources->pairs[i].key;
            const node *resource = resources->pairs[i].value;
            if (resource_is_type(resource, "AWS::EC2::VPC")) {
                have_vpc = 1;
                if (!property_is_true(resource, "EnableDnsSupport")) {
                    violation(c, "VPC must enable DNS support");
                }
                if (!property_is_true(resource, "EnableDnsHostnames")) {
                    violation(c, "VPC must enable DNS hostnames");
                }
                const node *metadata = map_get(resource, "Metadata");
                if (!node_contains(metadata, "!Ref ReleaseTag") ||
                    !node_contains(metadata, "!Ref ReleaseManifestSha256")) {
                    violation(c, "VPC Metadata must reference ReleaseTag and ReleaseManifestSha256");
                }
            } else if (resource_is_type(resource, "AWS::EC2::Subnet")) {
                have_subnet = 1;
                if (!property_is_true(resource, "MapPublicIpOnLaunch")) {
                    violation(c, "public subnet must set MapPublicIpOnLaunch true");
                }
            } else if (resource_is_type(resource, "AWS::EC2::SecurityGroup")) {
                have_security_group = 1;
                if (!egress_is_open(resource)) {
                    violation(c, "security group must allow all egress");
                }
            } else if (resource_is_type(resource, "AWS::S3::Bucket")) {
                have_bucket = 1;
                check_bucket(c, resource, name);
            }
        }
    }

    if (!have_vpc) {
        violation(c, "infra stack must create a VPC");
    }
    if (!have_subnet) {
        violation(c, "infra stack must create a public subnet");
    }
    if (!have_security_group) {
        violation(c, "infra stack must create a security group");
    }
    if (!have_bucket) {
        violation(c, "infra stack must create the artifact bucket");
    }
    if (!ssh_ingress_is_conditional(root)) {
        violation(c, "SSH ingress must be conditional on HasOperatorCidr");
    }
}

/* ------------------------------------------------------------- entrypoint */

static int run_check(const char *path, const char *text, size_t length, tc_mode mode) {
    arena storage = {0};
    parser p;
    memset(&p, 0, sizeof(p));
    p.path = path;
    p.arena = &storage;

    int status = 0;
    if (preprocess(&p, text, length) != 0 || p.errors > 0) {
        status = 2;
    } else {
        int indent = p.lines.nitems > 0 ? p.lines.items[0].indent : 0;
        node *root = parse_node(&p, indent);
        if (root == NULL || p.errors > 0) {
            status = 2;
        } else {
            checker c;
            c.path = path;
            c.violations = 0;
            check_sections(&c, root);
            if (mode == TC_MODE_OPERATOR) {
                check_operator(&c, root);
            } else {
                check_infra(&c, root);
            }
            status = c.violations > 0 ? 1 : 0;
        }
    }

    arena_reset(&storage);
    return status;
}

int tc_check_string(const char *text, size_t length, tc_mode mode) {
    if (text == NULL) {
        return 2;
    }
    return run_check("<string>", text, length, mode);
}

int tc_check_buffer(const char *path, const char *text, size_t length,
                    tc_mode mode) {
    if (text == NULL) {
        return 2;
    }
    return run_check(path != NULL ? path : "<string>", text, length, mode);
}

int tc_check_file(const char *path, tc_mode mode) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "%s: cannot open template\n", path);
        return 2;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        fprintf(stderr, "%s: cannot seek template\n", path);
        return 2;
    }
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        fprintf(stderr, "%s: cannot size template\n", path);
        return 2;
    }
    rewind(file);

    char *buffer = malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(file);
        return 2;
    }
    size_t read = fread(buffer, 1, (size_t)size, file);
    fclose(file);
    if (read != (size_t)size) {
        free(buffer);
        fprintf(stderr, "%s: short read\n", path);
        return 2;
    }
    buffer[read] = '\0';

    int status = run_check(path, buffer, read, mode);
    free(buffer);
    return status;
}

