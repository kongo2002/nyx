#ifndef __NYX_CONFIG_H__
#define __NYX_CONFIG_H__

#include "nyx.h"
#include "hash.h"
#include "list.h"

#include <stdio.h>
#include <yaml.h>

#define PARSE_HANDLER_SIZE (YAML_MAPPING_END_EVENT+1)

typedef struct parse_info_t parse_info_t;
typedef parse_info_t* (*handler_func_t)(parse_info_t*, yaml_event_t*, void*);

struct parse_info_t
{
    /** array of handler functions */
    handler_func_t handler[PARSE_HANDLER_SIZE];

    /** main application data */
    nyx_t *nyx;

    /** optional parent parsing information */
    parse_info_t *parent;

    /** arbitrary data */
    void *data;
};

typedef struct config_t config_t;
typedef struct config_value_t config_value_t;

typedef enum config_value_e
{
    CONFIG_MAP,
    CONFIG_LIST,
    CONFIG_NUMBER,
    CONFIG_STRING,
    CONFIG_SIZE
} config_value_e;

struct config_value_t
{
    config_value_e type;
    union
    {
        hash_t *map;
        config_value_t *list_type;
    };
};

struct config_t
{
    const char *key;
    config_value_t value;
};

struct config_parser_map
{
    const char *key;
    handler_func_t handler;
    void *data;
};

parse_info_t *
parse_info_new(nyx_t *nyx);

parse_info_t *
parse_info_new_child(parse_info_t *parent);

int
parse_config(nyx_t *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
