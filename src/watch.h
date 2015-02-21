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

#ifndef __NYX_WATCH_H__
#define __NYX_WATCH_H__

#include "hash.h"

typedef struct watch_t
{
    const char *name;
    const char *uid;
    const char *gid;
    const char **start;
    const char **stop;
    const char *dir;
    const char *pid_file;
    const char *log_file;
    const char *error_file;
    unsigned stop_timeout;
    unsigned max_cpu;
    unsigned long max_memory;
    hash_t *env;
    int invalid;
} watch_t;

watch_t *
watch_new(const char *name);

void
watch_dump(watch_t *watch);

void
watch_destroy(watch_t *watch);

int
watch_validate(watch_t *watch);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
