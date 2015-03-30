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

#ifndef __NYX_H__
#define __NYX_H__

#include "hash.h"
#include "list.h"
#include "proc.h"

#ifdef USE_PLUGINS
#include "plugins.h"
#endif

#include <stdint.h>
#include <sys/types.h>

typedef struct
{
    int quiet;
    int no_color;
    int no_daemon;
    int syslog;
    unsigned def_start_timeout;
    unsigned def_stop_timeout;
    unsigned polling_interval;
    unsigned history_size;
    const char *config_file;
    const char **commands;
#ifdef USE_PLUGINS
    const char *plugins;
#endif
} nyx_options_t;

typedef struct
{
    pid_t pid;
    int is_init;
    int is_daemon;
    const char *pid_dir;
    int event;
    void (*terminate_handler)(int);
    pthread_t *connector_thread;
    pthread_t *proc_thread;
    nyx_proc_t *proc;
    nyx_options_t options;
    hash_t *watches;
    list_t *states;
    hash_t *state_map;
#ifdef USE_PLUGINS
    plugin_repository_t *plugins;
#endif
} nyx_t;

void
print_usage(FILE *out);

int
is_daemon(nyx_t *nyx);

void
print_help(void) __attribute__((noreturn));

nyx_t *
nyx_initialize(int argc, char **args);

int
nyx_watches_init(nyx_t *nyx);

int
nyx_reload(nyx_t *nyx);

int
signal_eventfd(uint64_t signal, nyx_t *nyx);

void
setup_signals(nyx_t *nyx, void (*terminate_handler)(int));

void
nyx_destroy(nyx_t *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
