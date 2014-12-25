#ifndef __NYX_CONFIG_H__
#define __NYX_CONFIG_H__

#include "list.h"

#include <stdio.h>
#include <yaml.h>

typedef struct parse_state_t
{
    const char *filename;
    list_t *watches;
} parse_state_t;

typedef struct parse_info_t
{
    /** array of handler functions */
    int (*handler[YAML_MAPPING_END_EVENT+1])(struct parse_info_t*, yaml_event_t*);

    /** basic parse state */
    parse_state_t *state;

    /** arbitrary data */
    void *data;
} parse_info_t;

parse_state_t *
parse_state_new(const char *filename);

void
parse_state_destroy(parse_state_t *state);

parse_info_t *
parse_info_new(parse_state_t *state);

int
handle_stream(struct parse_info_t *info, yaml_event_t *event);

int
parse_config(const char *config_file);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
