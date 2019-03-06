/* Copyright 2014-2019 Gregor Uhlenheuer
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

#define _GNU_SOURCE

#include "fs.h"
#include "process.h"

#include <signal.h>

bool
clear_pid(const char *name, nyx_t *nyx)
{
    return remove_pid_file(nyx->pid_dir, name);
}

bool
valid_pid(pid_t pid, nyx_t *nyx)
{
    return pid > 0 &&
        pid != nyx->pid &&
        pid != nyx->forker_pid;
}

pid_t
determine_pid(const char *name, nyx_t *nyx)
{
    int32_t matched = 0;
    pid_t pid = 0;
    FILE *file = NULL;

    if (name == NULL)
        return 0;

    if ((file = open_pid_file(nyx->pid_dir, name, "re")) != NULL)
    {
        matched = fscanf(file, "%d", &pid);
        fclose(file);
    }

    if (matched == 1)
        return pid;

    return 0;
}

bool
check_process_running(pid_t pid)
{
    if (kill(pid, 0) == 0)
    {
        /* process is either running or a zombie */
        return true;
    }

    /* TODO: handle different errors? */

    return false;
}

bool
write_pid(pid_t pid, const char *name, nyx_t *nyx)
{
    int32_t written = 0;
    FILE *file = NULL;

    if (name == NULL)
        return false;

    if ((file = open_pid_file(nyx->pid_dir, name, "we")) != NULL)
    {
        written = fprintf(file, "%u", pid);
        fclose(file);
    }

    return written > 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
