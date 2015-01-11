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
#include "fs.h"
#include "hash.h"
#include "log.h"
#include "utils.h"
#include "watch.h"

#include <stdio.h>
#include <stdlib.h>

watch_t *
watch_new(const char *name)
{
    watch_t *watch = xcalloc(1, sizeof(watch_t));

    watch->name = name;

    return watch;
}

static void
dump_not_empty(const char *key, const char *value)
{
    if (value == NULL || *value == '\0')
        return;

    log_info("  %s: %s", key, value);
}

static void
dump_strings(const char *key, const char **values)
{
    const char **value;

    if (values == NULL || *values == NULL)
        return;

    log_info("  %s: [", key);

    value = values;

    while (*value)
    {
        log_info("   '%s'", *value);
        value++;
    }

    log_info("   ]");
}

void
watch_destroy(watch_t *watch)
{
    strings_free((char **)watch->start);

    if (watch->name)       free((void *)watch->name);
    if (watch->uid)        free((void *)watch->uid);
    if (watch->gid)        free((void *)watch->gid);
    if (watch->dir)        free((void *)watch->dir);
    if (watch->pid_file)   free((void *)watch->pid_file);
    if (watch->log_file)   free((void *)watch->log_file);
    if (watch->error_file) free((void *)watch->error_file);

    if (watch->env)
        hash_destroy(watch->env);

    free(watch);
    watch = NULL;
}

int
watch_validate(watch_t *watch)
{
    int result = 1, valid = 0;
    uid_t uid = 0;
    gid_t gid = 0;

    result &= watch->name && *watch->name;

    valid = watch->start != NULL && *watch->start != NULL;

    if (!valid)
        log_error("No 'start' specified");

    result &= valid;

    if (watch->uid)
    {
        valid = get_user(watch->uid, &uid, &gid);

        if (!valid)
            log_error("Invalid uid: %s", watch->uid);

        result &= valid;
    }

    if (watch->gid)
    {
        valid = get_group(watch->gid, &uid);

        if (!valid)
            log_error("Invalid gid: %s", watch->gid);

        result &= valid;
    }

    if (watch->pid_file)
    {
        valid = dir_writable(watch->pid_file);

        if (!valid)
        {
            log_error("PID file directory '%s' does not exist and/or "
                      "is not writable", watch->pid_file);
        }

        result &= valid;
    }

    if (watch->log_file)
    {
        valid = dir_writable(watch->log_file);

        if (!valid)
        {
            log_error("Log file directory '%s' does not exist and/or "
                      "is not writable", watch->log_file);
        }

        result &= valid;
    }
    if (watch->error_file)
    {
        valid = dir_writable(watch->error_file);

        if (!valid)
        {
            log_error("Error file directory '%s' does not exist and/or "
                      "is not writable", watch->error_file);
        }

        result &= valid;
    }

    return result;
}

void
watch_dump(watch_t *watch)
{
    log_info("Watch '%s'", watch->name);

    dump_strings("start", watch->start);

    dump_not_empty("uid", watch->uid);
    dump_not_empty("gid", watch->gid);
    dump_not_empty("dir", watch->dir);
    dump_not_empty("pid_file", watch->pid_file);
    dump_not_empty("log_file", watch->log_file);
    dump_not_empty("error_file", watch->error_file);

    if (watch->env)
    {
        log_info("  env: [");

        const char *key = NULL;
        void *data = NULL;
        hash_iter_t *iter = hash_iter_start(watch->env);

        while (hash_iter(iter, &key, &data))
        {
            log_info("   %s: %s", key, (char *)data);
        }

        log_info("   ]");
        free(iter);
    }
}

/* vim: set et sw=4 sts=4 tw=80: */
