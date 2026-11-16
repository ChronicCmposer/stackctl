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
        if (fn_sub->kind == NODE_SEQ && fn_sub->nitems >= 1 &&
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

/* ReleasePrefixes is a required, referenced parameter only when the template
 * creates the CI user (spec §6.3 "if CI user"). */
static const char *const OPERATOR_CI_PARAMS[] = {
    "ReleasePrefixes",
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

    const node *policy = map_get(resources, "OperatorPolicy");
    if (policy == NULL) {
        violation(c, "missing OperatorPolicy resource");
    } else if (node_contains(policy, "-certs-")) {
        violation(c, "OperatorPolicy must never grant the cert bucket");
    }
}

static void check_operator_s3_scope(checker *c, const node *n) {
    if (n == NULL) {
        return;
    }
    if (n->kind == NODE_SEQ) {
        for (size_t i = 0; i < n->nitems; i++) {
            check_operator_s3_scope(c, n->items[i]);
        }
        return;
    }
    if (n->kind != NODE_MAP) {
        return;
    }

    const node *action = map_get(n, "Action");
    const node *resource = map_get(n, "Resource");
    for (size_t i = 0; i < scalar_count(action); i++) {
        const node *entry = scalar_at(action, i);
        if (entry == NULL || !node_scalar_equals(entry, "s3:ListBucket")) {
            continue;
        }
        const node *condition = map_get(n, "Condition");
        if (condition == NULL || !node_contains(condition, "s3:prefix")) {
            violation(c, "operator ListBucket must be s3:prefix-conditioned");
        }
    }
    for (size_t i = 0; i < scalar_count(resource); i++) {
        const node *entry = scalar_at(resource, i);
        if (entry == NULL) {
            continue;
        }
        char literal[1024];
        int opaque = 0;
        if (resource_literal(entry->text, literal, sizeof(literal), &opaque) == 0) {
            continue;
        }
        int is_s3_object_action = action_list_contains(action, "s3:GetObject") ||
                                  action_list_contains(action, "s3:PutObject") ||
                                  action_list_contains(action, "s3:DeleteObject");
        if (is_s3_object_action && strstr(literal, "/releases/") == NULL) {
            violation(c, "operator S3 object access must be confined to releases/*: %s", literal);
        }
    }
    for (size_t i = 0; i < n->npairs; i++) {
        check_operator_s3_scope(c, n->pairs[i].value);
    }
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
 * Spec §3: the operator stack always creates the human/operator IAM user
 * `<project>` (provision mints its key) and that user must carry the operator
 * managed policy.  The CI user is conditional; the operator user is not.
 */
static void check_operator_user(checker *c, const node *root) {
    const node *resources = template_resources(root);
    if (resources == NULL || resources->kind != NODE_MAP) {
        violation(c, "operator stack must create an operator IAM user");
        return;
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
 * BakedAmiPublishRole is assumed by SSM Automation (EventBridge -> SSM
 * Automation target), never by EC2 directly.  An EC2 trust principal here is
 * silently unusable, so fail closed on anything but ssm.amazonaws.com.
 */
static void check_baked_ami_publish_role(checker *c, const node *root) {
    const node *role = map_get(template_resources(root), "BakedAmiPublishRole");
    if (role == NULL) {
        violation(c, "missing BakedAmiPublishRole resource");
        return;
    }
    const node *properties = map_get(role, "Properties");
    const node *assume = map_get(properties, "AssumeRolePolicyDocument");
    if (!trust_allows_service(map_get(assume, "Statement"), "ssm.amazonaws.com")) {
        violation(c, "BakedAmiPublishRole must trust ssm.amazonaws.com (SSM Automation)");
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
    const node *policy = map_get(template_resources(root), "OperatorPolicy");
    if (policy == NULL) {
        /* Missing OperatorPolicy is reported by check_operator_role_resources. */
        return;
    }
    if (find_statement(policy, "imagebuilder:CreateComponent") == NULL ||
        find_statement(policy, "imagebuilder:CreateImagePipeline") == NULL) {
        violation(c, "OperatorPolicy must grant imagebuilder:CreateComponent and "
                     "imagebuilder:CreateImagePipeline when EnableImageBuilder is declared");
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
    if (map_get(resources, "CiUser") != NULL) {
        check_required_params(c, root, OPERATOR_CI_PARAMS,
                              sizeof(OPERATOR_CI_PARAMS) / sizeof(OPERATOR_CI_PARAMS[0]));
    }
    check_required_actions(c, root, OPERATOR_ACTIONS,
                           sizeof(OPERATOR_ACTIONS) / sizeof(OPERATOR_ACTIONS[0]));

    const node *run = find_statement_with_condition(resources, "ec2:RunInstances",
                                                    "aws:TagKeys");
    if (run == NULL) {
        violation(c, "RunInstances is not tag-gated");
    } else {
        const node *condition = map_get(run, "Condition");
        if (!node_contains(condition, "ec2:CreateAction")) {
            violation(c, "RunInstances condition lacks ec2:CreateAction");
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
    check_baked_ami_publish_role(c, root);
    check_operator_image_builder_permissions(c, root);
    check_operator_s3_scope(c, map_get(resources, "OperatorPolicy"));
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

static void check_infra(checker *c, const node *root) {
    check_required_params(c, root, INFRA_PARAMS,
                          sizeof(INFRA_PARAMS) / sizeof(INFRA_PARAMS[0]));
    check_required_outputs(c, root, INFRA_OUTPUTS,
                           sizeof(INFRA_OUTPUTS) / sizeof(INFRA_OUTPUTS[0]));
    check_no_exports(c, root);
    check_stack_name_contract(c, root);
    check_image_builder_references(c, root);
    check_ami_id_arch_symmetry(c, root);

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

