/* Copyright 2014-2018 Gregor Uhlenheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

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

    /** array of optional jumpback functions */
    handler_func_t jumpback[PARSE_HANDLER_SIZE];

    /** main application data */
    nyx_t *nyx;

    /** optional parent parsing information */
    parse_info_t *parent;

    /** arbitrary data */
    void *data;

    /** toggle silent parsing operation/output */
    bool silent;
};

typedef enum
{
    CFG_SCALAR,
    CFG_LIST,
    CFG_MAP,
    CFG_SIZE
} config_parser_type_e;

struct config_parser_map
{
    const char *key;
    handler_func_t handler[CFG_SIZE];
    void *data;
};

parse_info_t *
parse_info_new(nyx_t *nyx, bool silent);

parse_info_t *
parse_info_new_child(parse_info_t *parent);

bool
parse_config(nyx_t *nyx, bool silent);

/* vim: set et sw=4 sts=4 tw=80: */
