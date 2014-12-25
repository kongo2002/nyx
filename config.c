#include "config.h"

static void
reset_handlers(parse_info_t *info)
{
    size_t handler_size = sizeof(handler_func_t);
    memset(info->handler, 0, handler_size * PARSE_HANDLER_SIZE);
}

static parse_info_t *
handle_document_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_document: end");

    return info;
}

static parse_info_t *
handle_document(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_document: start");

    reset_handlers(info);
    info->handler[YAML_DOCUMENT_END_EVENT] = &handle_document_end;

    return info;
}

static parse_info_t *
handle_stream_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    puts("handle_stream: end");

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
    parent->parent = info;

    return info;
}

int
parse_config(const char *config_file)
{
    int success = 1;
    FILE *cfg;
    yaml_parser_t parser;
    yaml_event_t event;
    handler_func_t handler = NULL;

    parse_state_t *state = parse_state_new(config_file);
    parse_info_t *info = parse_info_new(state);

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

        switch (event.type)
        {
            case YAML_NO_EVENT: puts("No event!"); break;
            /* Stream start/end */
            case YAML_STREAM_START_EVENT: puts("STREAM START"); break;
            case YAML_STREAM_END_EVENT:   puts("STREAM END");   break;
            /* Block delimeters */
            case YAML_DOCUMENT_START_EVENT: puts("Start Document"); break;
            case YAML_DOCUMENT_END_EVENT:   puts("End Document");   break;
            case YAML_SEQUENCE_START_EVENT: puts("Start Sequence"); break;
            case YAML_SEQUENCE_END_EVENT:   puts("End Sequence");   break;
            case YAML_MAPPING_START_EVENT:  puts("Start Mapping");  break;
            case YAML_MAPPING_END_EVENT:    puts("End Mapping");    break;
            /* Data */
            case YAML_ALIAS_EVENT:  printf("Got alias (anchor %s)\n", event.data.alias.anchor); break;
            case YAML_SCALAR_EVENT: printf("Got scalar (value %s)\n", event.data.scalar.value); break;
        }

        handler = info->handler[event.type];
        if (handler != NULL)
        {
            if (!handler(info, &event, NULL))
            {
                puts("handler returned without success");
                break;
            }
        }
        else
        {
            fprintf(stderr, "No handler for event %d found\n", event.type);
        }

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
