#ifndef __NYX_CONFIG_H__
#define __NYX_CONFIG_H__

#include "list.h"
#include "map.h"

#include <stdio.h>
#include <yaml.h>

#define PARSE_HANDLER_SIZE (YAML_MAPPING_END_EVENT+1)

typedef struct parse_state_t parse_state_t;
typedef struct parse_info_t parse_info_t;
typedef parse_info_t* (*handler_func_t)(parse_info_t*, yaml_event_t*, void*);

struct parse_state_t
{
    const char *filename;
    hash_t *watches;
};

struct parse_info_t
{
    /** array of handler functions */
    handler_func_t handler[PARSE_HANDLER_SIZE];

    /** basic parse state */
    parse_state_t *state;

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
        config_t *map;
        config_value_t *list_type;
    };
};

struct config_t
{
    const char *key;
    config_value_t value;
};

#define CFG_NUMBER(x) \
    { .key = (x), .value = { .type = CONFIG_NUMBER } }

#define CFG_STRING(x) \
    { .key = (x), .value = { .type = CONFIG_STRING } }

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
