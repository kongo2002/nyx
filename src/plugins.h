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

#ifndef __NYX_PLUGINS_H__
#define __NYX_PLUGINS_H__

#include "hash.h"
#include "list.h"

#define NYX_PLUGIN_INIT_FUNC "plugin_init"

typedef struct
{
    const char *name;
    void *handle;
} plugin_t;

typedef struct
{
    const char *version;
    hash_t *config;

    list_t *state_callbacks;
    list_t *destroy_callbacks;
} plugin_manager_t;

typedef struct
{
    plugin_manager_t *manager;
    list_t *plugins;
} plugin_repository_t;

typedef void (*plugin_state_callback)(const char *, int, pid_t, void *);

typedef void (*plugin_destroy_callback)(void *);

typedef struct
{
    void * state_data;
    plugin_state_callback state_callback;
} plugin_state_callback_info_t;

typedef struct
{
    void * destroy_data;
    plugin_destroy_callback destroy_callback;
} plugin_destroy_callback_info_t;

typedef int (*plugin_init_func)(plugin_manager_t *manager);

plugin_repository_t *
discover_plugins(const char *directory, hash_t *config);

void
plugin_register_state_callback(plugin_manager_t *manager,
        plugin_state_callback callback,
        void *userdata);

void
plugin_register_destroy_callback(plugin_manager_t *manager,
        plugin_destroy_callback callback,
        void *userdata);

void
plugin_repository_destroy(plugin_repository_t *repository);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
