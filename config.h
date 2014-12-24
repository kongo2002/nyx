#ifndef __NYX_CONFIG_H__
#define __NYX_CONFIG_H__

#include "list.h"

#include <stdio.h>
#include <yaml.h>

typedef struct parse_info
{
    /** array of handler functions */
    int (*handler[YAML_MAPPING_END_EVENT+1])(struct parse_info*, yaml_event_t*);

    /** arbitrary data */
    void *data;
} parse_info;

typedef struct parse_state
{
    const char *filename;
    list_t *watches;
} parse_state;

parse_state *
parse_state_new(const char *filename);

void
parse_state_destroy(parse_state *state);

parse_info *
parse_info_new(void);

int
handle_stream(struct parse_info *info, yaml_event_t *event);

int
parse_config(const char *config_file);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
