#ifndef __NYX_CONFIG_H__
#define __NYX_CONFIG_H__

#include "list.h"

#include <stdio.h>
#include <yaml.h>

#define PARSE_HANDLER_SIZE (YAML_MAPPING_END_EVENT+1)

typedef struct parse_state_t
{
    const char *filename;
    list_t *watches;
} parse_state_t;

typedef struct parse_info_t
{
    /** array of handler functions */
    struct parse_info_t* (*handler[PARSE_HANDLER_SIZE])(struct parse_info_t*, yaml_event_t*, void*);

    /** basic parse state */
    parse_state_t *state;

    /** optional parent parsing information */
    struct parse_info_t *parent;

    /** arbitrary data */
    void *data;
} parse_info_t;

typedef parse_info_t* (*handler_func_t)(parse_info_t*, yaml_event_t*, void*);

parse_state_t *
parse_state_new(const char *filename);

void
parse_state_destroy(parse_state_t *state);

parse_info_t *
parse_info_new(parse_state_t *state);

parse_info_t *
parse_info_new_child(parse_info_t *parent);

int
parse_config(const char *config_file);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
