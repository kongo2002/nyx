#include "config.h"

int
handle_stream(struct parse_info *info, yaml_event_t *event)
{
    puts("handle_stream");

    return 1;
}

int
parse_config(const char *config_file)
{
    int success = 1;
    FILE *cfg;
    yaml_parser_t parser;
    yaml_event_t event;

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

        if (event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    }
    while (event.type != YAML_STREAM_END_EVENT);

    /* cleanup */
    yaml_parser_delete(&parser);
    fclose(cfg);

    return success;
}

/* vim: set et sw=4 sts=4 tw=80: */
