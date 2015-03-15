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

#include "def.h"
#include "log.h"
#include "plugins.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static const char *
get_plugin(const char *name)
{
    if (name == NULL || *name == '\0')
        return NULL;

    char *last_dot = strrchr(name, '.');

    if (!last_dot || strncmp(last_dot, ".so", 3))
        return NULL;

    size_t len = last_dot - name;
    if (!len)
        return NULL;

    char *plugin_name = xcalloc(len+1, sizeof(char));
    strncpy(plugin_name, name, len);

    return plugin_name;
}

static plugin_t *
init_plugin(const char *path, const char *name)
{
    size_t length = strlen(path) + strlen(name) + 4;
    char *fullpath = xcalloc(length+1, sizeof(char));

    snprintf(fullpath, length, "%s/%s.so", path, name);

    void *handle = dlopen(fullpath, RTLD_NOW);

    free(fullpath);

    if (!handle)
    {
        log_error("Failed to load plugin '%s': %s", name, dlerror());
        return NULL;
    }

    plugin_t *plugin = xcalloc1(sizeof(plugin_t));

    plugin->name = name;
    plugin->handle = handle;

    return plugin;
}

int
discover_plugins(const char *directory, list_t *plugins)
{
    int found = 0;

    if (directory == NULL || *directory == '\0')
        return found;

    DIR *dir = opendir(directory);
    if (dir)
    {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL)
        {
            const char *plugin_name = get_plugin(entry->d_name);
            if (!plugin_name)
                continue;

            log_debug("Found plugin '%s'", plugin_name);
        }

        closedir(dir);
    }

    return found;
}

/* vim: set et sw=4 sts=4 tw=80: */
