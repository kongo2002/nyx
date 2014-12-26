#include "config.h"
#include "map.h"
#include "nyx.h"
#include "watch.h"

#include <string.h>

static const char * yaml_event_names[] =
{
    "YAML_NO_EVENT",
    "YAML_STREAM_START_EVENT",
    "YAML_STREAM_END_EVENT",
    "YAML_DOCUMENT_START_EVENT",
    "YAML_DOCUMENT_END_EVENT",
    "YAML_ALIAS_EVENT",
    "YAML_SCALAR_EVENT",
    "YAML_SEQUENCE_START_EVENT",
    "YAML_SEQUENCE_END_EVENT",
    "YAML_MAPPING_START_EVENT",
    "YAML_MAPPING_END_EVENT"
};

static parse_info_t *
handle_mapping(parse_info_t *info, yaml_event_t *event, void *data);

static parse_info_t *
handle_scalar_key(parse_info_t *info, yaml_event_t *event, void *data);

static parse_info_t *
handle_scalar_value(parse_info_t *info, yaml_event_t *event, void *data);

static parse_info_t *
handle_watch_map_key(parse_info_t *info, yaml_event_t *event, void *data);

static parse_info_t *
handle_watch(parse_info_t *info, yaml_event_t *event, void *data);

static int
check_event_type(yaml_event_t *event, yaml_event_type_t event_type)
{
    if (event->type != event_type)
    {
        fprintf(stderr, "Expecting '%s', but found '%s'\n",
                yaml_event_names[event_type],
                yaml_event_names[event->type]);
        return 0;
    }

    return 1;
}

static const char *
get_scalar_value(yaml_event_t *event)
{
    if (!check_event_type(event, YAML_SCALAR_EVENT))
        return NULL;

    return (char *)event->data.scalar.value;
}

static handler_func_t
get_handler_from_map(struct config_parser_map *map, const char *key)
{
    struct config_parser_map *mapping = map;

    while (mapping && mapping->key)
    {
        if (!strcmp(mapping->key, key))
            return mapping->handler;

        mapping++;
    }

    return NULL;
}

static handler_func_t
get_handler_from_map_fallback(struct config_parser_map *map, const char *key, handler_func_t fallback)
{
    handler_func_t handler = get_handler_from_map(map, key);

    if (handler != NULL)
        return handler;

    fprintf(stderr, "Unknown config key '%s'\n", key);

    return fallback;
}

static void
reset_handlers(parse_info_t *info)
{
    size_t handler_size = sizeof(handler_func_t);
    memset(info->handler, 0, handler_size * PARSE_HANDLER_SIZE);
}

static parse_info_t *
parser_up(parse_info_t *info, yaml_event_t *event, void *data)
{
    if (info->parent == NULL)
    {
        fprintf(stderr,
                "topmost parser without parent - invalid config [%s]\n",
                yaml_event_names[event->type]);
        return NULL;
    }

    parse_info_t *parent = info->parent;
    free(info);

    return parent;
}

static parse_info_t *
handle_stream_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_stream: end");

    return info;
}

static parse_info_t *
handle_document_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_document: end");

    reset_handlers(info);
    info->handler[YAML_STREAM_END_EVENT] = &handle_stream_end;

    return info;
}

static parse_info_t *
handle_scalar_value(parse_info_t *info, yaml_event_t *event, void *data)
{
    if (event->type != YAML_SCALAR_EVENT)
    {
        fprintf(stderr, "Expecting scalar value, but found '%s'\n",
                yaml_event_names[event->type]);
        return NULL;
    }

    printf("handle_scalar_value: '%s'\n", event->data.scalar.value);

    info->handler[YAML_SCALAR_EVENT] = &handle_scalar_key;

    return info;
}

static parse_info_t *
handle_scalar_key(parse_info_t *info, yaml_event_t *event, void *data)
{
    const char *key;
    struct config_parser_map *map = NULL;
    handler_func_t handler = NULL;

    key = get_scalar_value(event);

    if (key == NULL)
        return NULL;

    /* handler lookup */
    if (data != NULL)
    {
        map = data;
        handler = get_handler_from_map(map, key);
    }

    if (handler == NULL)
    {
        fprintf(stderr, "Unknown config key '%s'\n", key);

        info->handler[YAML_SCALAR_EVENT] = &handle_scalar_value;
        info->handler[YAML_MAPPING_START_EVENT] = &handle_mapping;
    }
    else
    {
        printf("found handler for key '%s'\n", key);

        info->handler[YAML_SCALAR_EVENT] = handler;
        info->handler[YAML_MAPPING_START_EVENT] = handler;
        info->handler[YAML_SEQUENCE_START_EVENT] = handler;
    }

    return info;
}

static parse_info_t *
handle_mapping_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_mapping: end");

    return parser_up(info, event, data);
}

static parse_info_t *
handle_mapping(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_mapping: start");

    parse_info_t *new = parse_info_new_child(info);

    new->handler[YAML_SCALAR_EVENT] = &handle_scalar_key;
    new->handler[YAML_MAPPING_END_EVENT] = &handle_mapping_end;

    return new;
}

static parse_info_t *
handle_document(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_document: start");

    reset_handlers(info);
    info->handler[YAML_MAPPING_START_EVENT] = &handle_mapping;
    info->handler[YAML_DOCUMENT_END_EVENT] = &handle_document_end;

    return info;
}

static parse_info_t *
handle_stream(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_stream: start");

    reset_handlers(info);
    info->handler[YAML_DOCUMENT_START_EVENT] = &handle_document;
    info->handler[YAML_STREAM_END_EVENT] = &handle_stream_end;

    return info;
}

#define DECLARE_WATCH_VALUE_FUNC(name_) \
    static parse_info_t * \
    handle_watch_map_value_##name_(parse_info_t *info, yaml_event_t *event, void *data) \
    { \
        puts("handle_watch_map_value_"); \
        watch_t *watch = data; \
        const char *value = get_scalar_value(event); \
        if (value == NULL || watch == NULL) \
            return NULL; \
        watch->name_ = value; \
        info->handler[YAML_SCALAR_EVENT] = &handle_watch_map_key; \
        return info; \
    }

DECLARE_WATCH_VALUE_FUNC(name)
DECLARE_WATCH_VALUE_FUNC(uid)
DECLARE_WATCH_VALUE_FUNC(gid)
DECLARE_WATCH_VALUE_FUNC(start)
DECLARE_WATCH_VALUE_FUNC(dir)

#undef DECLARE_WATCH_VALUE_FUNC

static struct config_parser_map watch_value_map[] =
{
    { .key = "name", .handler = handle_watch_map_value_name },
    { .key = "uid", .handler = handle_watch_map_value_uid },
    { .key = "gid", .handler = handle_watch_map_value_gid },
    { .key = "start", .handler = handle_watch_map_value_start },
    { .key = "dir", .handler = handle_watch_map_value_dir },
    { NULL }
};

static parse_info_t *
unknown_watch_key(parse_info_t *info, yaml_event_t *event, void *data)
{
    /* no op */
    return info;
}

static parse_info_t *
handle_watch_map_key(parse_info_t *info, yaml_event_t *event, void *data)
{
    const char *key;
    watch_t *watch = data;
    handler_func_t handler = NULL;

    puts("handle_watch_map_key");

    key = get_scalar_value(event);

    /* empty key or not a scalar at all */
    if (key == NULL || watch == NULL)
        return NULL;

    handler = get_handler_from_map_fallback(watch_value_map, key, unknown_watch_key);

    info->handler[YAML_SCALAR_EVENT] = handler;

    return info;
}

static parse_info_t *
handle_watch_map_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    parse_info_t *parent = parser_up(info, event, data);

    /* reset data (last watch instance) */
    parent->data = NULL;
    parent->handler[YAML_SCALAR_EVENT] = &handle_watch;

    return parent;
}

static parse_info_t *
handle_watch_map(parse_info_t *info, yaml_event_t *event, void *data)
{
    parse_info_t *new = NULL;

    puts("handle_watch_map");

    new = parse_info_new_child(info);

    new->handler[YAML_SCALAR_EVENT] = &handle_watch_map_key;
    new->handler[YAML_MAPPING_END_EVENT] = &handle_watch_map_end;

    return new;
}

static parse_info_t *
handle_watch(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle watch");

    const char *name = get_scalar_value(event);

    if (name == NULL)
        return NULL;

    watch_t *watch = calloc(1, sizeof(watch_t));

    if (watch == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    hash_add(info->nyx->watches, name, watch);

    reset_handlers(info);
    info->handler[YAML_MAPPING_START_EVENT] = &handle_watch_map;
    info->handler[YAML_MAPPING_END_EVENT] = &handle_mapping_end;

    info->data = watch;

    return info;
}

static parse_info_t *
handle_watches(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle watches");

    reset_handlers(info);

    /* either name of the watch
     * or a sequence of watches */
    info->handler[YAML_SCALAR_EVENT] = &handle_watch;

    return info;
}

static struct config_parser_map root_map[] =
{
    { .key = "watches", .handler = &handle_watches },
    { NULL }
};

void *
config_initialize(nyx_t *nyx)
{
    return NULL;
}

parse_info_t *
parse_info_new(nyx_t *nyx)
{
    parse_info_t *info = calloc(1, sizeof(parse_info_t));

    if (info == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    info->nyx = nyx;
    info->handler[YAML_STREAM_START_EVENT] = handle_stream;
    info->data = &root_map;

    return info;
}

parse_info_t *
parse_info_new_child(parse_info_t *parent)
{
    parse_info_t *info = calloc(1, sizeof(parse_info_t));

    if (info == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    info->nyx = parent->nyx;
    info->parent = parent;

    /* migrate data to child if given */
    info->data = parent->data;

    return info;
}

static void
parse_info_destroy(parse_info_t *info)
{
    parse_info_t *next = info;

    while (next)
    {
        next = info->parent;

        free(info);
        info = next;
    }
}

static void
unexpected_element(yaml_event_t *event)
{
    const char *type = yaml_event_names[event->type];

    if (event->start_mark.column > 0)
    {
        fprintf(stderr,
                "Unexpected element '%s' [line %zu, col %zu]\n",
                type,
                event->start_mark.line,
                event->start_mark.column);
    }
    else
    {
        fprintf(stderr,
                "Unexpected element '%s' [line %zu]\n",
                type,
                event->start_mark.line);
    }
}

int
parse_config(nyx_t *nyx)
{
    int success = 1;
    FILE *cfg = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    handler_func_t handler = NULL;

    /* read input file */
    cfg = fopen(nyx->config_file, "r");
    if (cfg == NULL)
    {
        perror("nyx: fopen");
        return 0;
    }

    /* initialize yaml parser */
    if (!yaml_parser_initialize(&parser))
    {
        fprintf(stderr, "Failed to parse config file %s\n", nyx->config_file);
        return 0;
    }

    parse_info_t *info = parse_info_new(nyx);
    parse_info_t *new_info = NULL;

    yaml_parser_set_input_file(&parser, cfg);

    /* start parsing */
    do
    {
        if (!yaml_parser_parse(&parser, &event))
        {
           printf("Parser error %d\n", parser.error);
           success = 0;
           break;
        }

        handler = info->handler[event.type];
        if (handler != NULL)
        {
            new_info = handler(info, &event, info->data);
            if (new_info == NULL)
            {
                fprintf(stderr, "Invalid configuration '%s'\n",
                        nyx->config_file);
                success = 0;
                break;
            }

            info = new_info;
        }
        else
            unexpected_element(&event);

        if (event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    }
    while (event.type != YAML_STREAM_END_EVENT);

    /* cleanup */
    yaml_parser_delete(&parser);

    parse_info_destroy(info);
    fclose(cfg);

    if (success)
        printf("Parsed %d watch definitions\n", hash_count(nyx->watches));

    return success;
}

/* vim: set et sw=4 sts=4 tw=80: */
