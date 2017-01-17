/* Copyright 2014-2017 Gregor Uhlenheuer
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

#include "hash.h"
#include "list.h"
#include "proc.h"

#ifdef USE_PLUGINS
#include "plugins.h"
#endif

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct
{
    bool quiet;
    bool no_color;
    bool no_daemon;
    bool syslog;
    int32_t http_port;
    uint32_t def_start_timeout;
    uint32_t def_stop_timeout;
    uint32_t polling_interval;
    uint32_t check_interval;
    uint32_t history_size;
    const char *config_file;
    const char *log_file;
    const char **commands;
#ifdef USE_PLUGINS
    const char *plugins;
    hash_t *plugin_config;
#endif
} nyx_options_t;

typedef struct
{
    pid_t pid;
    bool is_init;
    bool is_daemon;
    const char *pid_dir;
    int32_t event;
    int32_t event_pipe[2];
    void (*terminate_handler)(int32_t);
    pthread_t *connector_thread;
    pthread_t *proc_thread;
    nyx_proc_t *proc;
    nyx_options_t options;
    hash_t *watches;
    list_t *states;
    hash_t *state_map;
    int32_t forker_pipe;
#ifdef USE_PLUGINS
    plugin_repository_t *plugins;
#endif
} nyx_t;

typedef enum
{
    NYX_SUCCESS,
    NYX_FAILURE,
    NYX_INVALID_USAGE,
    NYX_INVALID_CONFIG,
    NYX_NO_COMMAND,
    NYX_INVALID_COMMAND,
    NYX_COMMAND_FAILED,
    NYX_INSTANCE_RUNNING,
    NYX_NO_VALID_WATCH,
    NYX_NO_PID_DIR,
    NYX_FAILED_DAEMONIZE,
    NYX_NO_DAEMON_FOUND
} nyx_error_e;

void
print_usage(FILE *out);

int
is_daemon(nyx_t *nyx);

void
print_help(void) __attribute__((noreturn));

nyx_t *
nyx_initialize(int argc, char **args, nyx_error_e *error);

bool
nyx_watches_init(nyx_t *nyx);

bool
nyx_reload(nyx_t *nyx);

bool
signal_eventfd(uint64_t signum, nyx_t *nyx);

void
setup_signals(nyx_t *nyx, void (*terminate_handler)(int));

void
nyx_destroy(nyx_t *nyx);

/* vim: set et sw=4 sts=4 tw=80: */
