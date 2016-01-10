/* Copyright 2014-2016 Gregor Uhlenheuer
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

typedef enum process_event_t
{
    EVENT_FORK,
    EVENT_EXIT,
    NUM_EVENTS
} process_event_t;

typedef struct process_event_fork_t
{
    int32_t parent_pid;
    int32_t parent_thread_group_id;
    int32_t child_pid;
    int32_t child_thread_group_id;
} process_event_fork_t;

typedef struct process_event_exit_t
{
    int32_t pid;
    int32_t exit_code;
    int32_t exit_signal;
    int32_t thread_group_id;
} process_event_exit_t;

typedef struct process_event_data_t
{
    process_event_t type;
    union
    {
        process_event_fork_t fork;
        process_event_exit_t exit;
    } data;
} process_event_data_t;

typedef bool (*process_handler_t)(pid_t pid, process_event_data_t *event_data, nyx_t *nyx);

bool
event_loop(nyx_t *nyx, process_handler_t handler);

/* vim: set et sw=4 sts=4 tw=80: */
