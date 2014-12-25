#include "config.h"

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

        /* TODO: return NULL instead? */
        return info;
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
handler_scalar(parse_info_t *info, yaml_event_t *event, void *data)
{
    printf("handle_scalar: '%s'\n", event->data.scalar.value);

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

    new->handler[YAML_SCALAR_EVENT] = &handler_scalar;
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

parse_state_t *
parse_state_new(const char *filename)
{
    parse_state_t *state = calloc(1, sizeof(parse_state_t));

    if (state == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    state->filename = filename;
    state->watches = list_new();

    return state;
}

void
parse_state_destroy(parse_state_t *state)
{
    if (state == NULL)
        return;

    list_clear_destroy(state->watches);

    free(state);
    state = NULL;
}

parse_info_t *
parse_info_new(parse_state_t *state)
{
    parse_info_t *info = calloc(1, sizeof(parse_info_t));

    if (info == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    info->state = state;
    info->handler[YAML_STREAM_START_EVENT] = handle_stream;

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

    info->state = parent->state;
    info->parent = parent;

    return info;
}

static void
unexpected_element(yaml_event_t *event)
{
    const char *type = yaml_event_names[event->type];

    if (event->start_mark.column > 0)
    {
        fprintf(stderr,
                "Unexpected element '%s' [line %lu, col %lu]\n",
                type,
                event->start_mark.line,
                event->start_mark.column);
    }
    else
    {
        fprintf(stderr,
                "Unexpected element '%s' [line %lu]\n",
                type,
                event->start_mark.line);
    }
}

int
parse_config(const char *config_file)
{
    int success = 1;
    FILE *cfg = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    handler_func_t handler = NULL;

    /* read input file */
    cfg = fopen(config_file, "r");
    if (cfg == NULL)
    {
        perror("nyx: fopen");
        return 0;
    }

    /* initialize yaml parser */
    if (!yaml_parser_initialize(&parser))
    {
        fprintf(stderr, "Failed to parse config file %s\n", config_file);
        return 0;
    }

    parse_state_t *state = parse_state_new(config_file);
    parse_info_t *info = parse_info_new(state);

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
            info = handler(info, &event, NULL);
            if (info == NULL)
            {
                puts("handler returned without success");
                break;
            }
        }
        else
            unexpected_element(&event);

        if (event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    }
    while (event.type != YAML_STREAM_END_EVENT);

    /* cleanup */
    parse_state_destroy(state);
    free(info);
    yaml_parser_delete(&parser);

    fclose(cfg);

    return success;
}

/* vim: set et sw=4 sts=4 tw=80: */
