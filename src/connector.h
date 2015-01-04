/* Copyright 2014-2015 Gregor Uhlenheuer
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

#ifndef __NYX_CONNECTOR_H__
#define __NYX_CONNECTOR_H__

#include "nyx.h"

typedef enum
{
    CMD_PING,
    CMD_VERSION,
    CMD_TERMINATE,
    CMD_STOP,
    CMD_START,
    CMD_SIZE
} connector_command_e;

typedef int (*command_handler)(connector_command_e, const char *, nyx_t *);

typedef struct
{
    connector_command_e type;
    const char *name;
    command_handler handler;
    size_t cmd_length;
} command_t;

const char *
connector_call(command_t *cmd);

command_t *
parse_command(const char *input);

void
connector_close();

void *
connector_start(void *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
