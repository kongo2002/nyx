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

#include "def.h"
#include "fs.h"
#include "hash.h"
#include "log.h"
#include "utils.h"
#include "watch.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

bool
is_all(const char *name)
{
    return name != NULL &&
        strlen(name) == 3 &&
        strncasecmp(name, "all", 3) == 0;
}

watch_t *
watch_new(const char *name)
{
    watch_t *watch = xcalloc(1, sizeof(watch_t));

    watch->name = name;

    /* default to port 80 for HTTP check */
    watch->http_check_port = 80;

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
    strings_free((char **)watch->stop);

    if (watch->name)       free((void *)watch->name);
    if (watch->uid)        free((void *)watch->uid);
    if (watch->gid)        free((void *)watch->gid);
    if (watch->dir)        free((void *)watch->dir);
    if (watch->pid_file)   free((void *)watch->pid_file);
    if (watch->log_file)   free((void *)watch->log_file);
    if (watch->error_file) free((void *)watch->error_file);
    if (watch->http_check) free((void *)watch->http_check);

    if (watch->env)
        hash_destroy(watch->env);

    free(watch);
}

bool
watch_validate(watch_t *watch)
{
    bool result = true, valid = false;
    uid_t uid = 0;
    gid_t gid = 0;

    result &= watch->name && *watch->name;

    if (is_all(watch->name))
    {
        log_error("Reserved name 'all' used");
        result = false;
    }

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
    dump_strings("stop", watch->stop);

    dump_not_empty("uid", watch->uid);
    dump_not_empty("gid", watch->gid);
    dump_not_empty("dir", watch->dir);
    dump_not_empty("pid_file", watch->pid_file);
    dump_not_empty("log_file", watch->log_file);
    dump_not_empty("error_file", watch->error_file);
    dump_not_empty("http_check", watch->http_check);

    if (watch->http_check)
    {
        if (watch->http_check_port)
            log_info("  http_check_port: %u", watch->http_check_port);

        log_info("  http_check_method: %s",
                http_method_to_string(watch->http_check_method));
    }

    if (watch->max_memory)
        log_info("  max_memory: %" PRId64, watch->max_memory);

    if (watch->max_cpu)
        log_info("  max_cpu: %u%%", watch->max_cpu);

    if (watch->stop_timeout)
        log_info("  stop_timeout: %u", watch->stop_timeout);

    if (watch->port_check)
        log_info("  port_check: %u", watch->port_check);

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
