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

typedef enum
{
    CMD_PING,
    CMD_VERSION,
    CMD_TERMINATE,
    CMD_STOP,
    CMD_START,
    CMD_SIZE
} connector_command_e;

const char *
connector_call(connector_command_e cmd);

int
parse_command(const char *input, connector_command_e *cmd);

void
connector_close();

void *
connector_start(void *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
