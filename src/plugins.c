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
init_plugin(const char *path, const char *name, plugin_manager_t *manager)
{
    size_t length = strlen(path) + strlen(name) + 5;
    char *fullpath = xcalloc(length, sizeof(char));

    snprintf(fullpath, length, "%s/%s.so", path, name);

    /* try to acquire dynamic handle */
    void *handle = dlopen(fullpath, RTLD_NOW);

    free(fullpath);

    if (!handle)
    {
        log_error("Failed to load plugin '%s': %s", name, dlerror());
        return NULL;
    }

    /* we got the dynamic handle, now try to find the initialization function */
    plugin_init_func init_func = dlsym(handle, NYX_PLUGIN_INIT_FUNC);

    if (init_func == NULL)
    {
        log_error("Plugin '%s' does not contain mandatory init func '"
                NYX_PLUGIN_INIT_FUNC "'", name);
        dlclose(handle);
        return NULL;
    }

    /* invoke the plugin's initialization function */
    int retval = init_func(manager);

    if (retval < 1)
    {
        log_error("Plugin '%s': initialization failed to return with success: %d",
                name, retval);
        dlclose(handle);
        return NULL;
    }

    plugin_t *plugin = xcalloc1(sizeof(plugin_t));

    plugin->name = name;
    plugin->handle = handle;

    return plugin;
}

static void
plugin_destroy(void *plugin)
{
    plugin_t *p = plugin;

    if (p == NULL)
        return;

    free((void *)p->name);

    if (p->handle)
        dlclose(p->handle);

    free(p);
}

static plugin_repository_t *
plugin_repository_new(void)
{
    plugin_repository_t *repo = xcalloc1(sizeof(plugin_repository_t));

    repo->plugins = list_new(plugin_destroy);

    repo->manager = xcalloc1(sizeof(plugin_manager_t));
    repo->manager->version = NYX_VERSION;

    return repo;
}

void
plugin_repository_destroy(plugin_repository_t *repository)
{
    if (repository == NULL)
        return;

    free(repository->manager);
    list_destroy(repository->plugins);

    free(repository);
}

plugin_repository_t *
discover_plugins(const char *directory)
{
    plugin_repository_t *repo = NULL;

    if (directory == NULL || *directory == '\0')
        return NULL;

    log_debug("Searching plugin directory '%s'", directory);

    DIR *dir = opendir(directory);
    if (dir)
    {
        repo = plugin_repository_new();

        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL)
        {
            const char *plugin_name = get_plugin(entry->d_name);
            if (!plugin_name)
                continue;

            log_debug("Found plugin '%s'", plugin_name);

            plugin_t *plugin = init_plugin(directory, plugin_name, repo->manager);

            /* plugin initialization failed */
            if (plugin == NULL)
            {
                log_warn("Failed to load plugin '%s'", plugin_name);
                free((void *)plugin_name);
            }
            else
            {
                list_add(repo->plugins, plugin);
                log_info("Successfully loaded plugin '%s'", plugin_name);
            }
        }

        closedir(dir);

        /* we can immediately release the whole plugin repository
         * in case we could not initialize at least one plugin */
        if (list_size(repo->plugins) < 1)
        {
            plugin_repository_destroy(repo);
            repo = NULL;
        }
    }

    return repo;
}

/* vim: set et sw=4 sts=4 tw=80: */
