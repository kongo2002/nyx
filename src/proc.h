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

#pragma once

#include "list.h"
#include "stack.h"
#include "watch.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum
{
    PROC_MAX_CPU,
    PROC_MAX_MEMORY,
    PROC_PORT_NOT_OPEN,
    PROC_HTTP_CHECK_FAILED
} proc_event_e;

typedef struct
{
    uint64_t user_time;        /* 14 */
    uint64_t system_time;      /* 15 */
    int64_t child_user_time;   /* 16 */
    int64_t child_system_time; /* 17 */
    uint64_t virtual_size;     /* 23 */
    int64_t resident_set_size; /* 24 */

    uint64_t total_time;

} sys_info_t;

DECLARE_STACK(uint64_t, long)
DECLARE_STACK(double, double)

typedef struct
{
    /** process ID */
    pid_t pid;
    /** process statistics */
    sys_info_t info;
    /** process CPU usage (in percent) */
    stack_double_t *cpu_usage;
    /** process memory usage (in kb) */
    stack_long_t *mem_usage;
    /** process name */
    const char *name;
    /** associated watch */
    watch_t *watch;
} proc_stat_t;

typedef struct
{
    uint64_t user_time;
    uint64_t nice_time;
    uint64_t system_time;
    uint64_t idle_time;
    uint64_t iowait_time;

    uint64_t total;
    uint64_t period;
} sys_proc_stat_t;

typedef struct
{
    /** total system memory (in kB) */
    uint64_t total_memory;
    /** system page size (in bytes) */
    int64_t page_size;
    /** number of CPUs */
    int32_t num_cpus;
    /** current system statistics */
    sys_proc_stat_t sys_proc;
    /** list of watched processes */
    list_t *processes;
    /** process event handler */
    bool (*event_handler)(proc_event_e, proc_stat_t *, void *);
} nyx_proc_t;

nyx_proc_t *
nyx_proc_new(void);

nyx_proc_t *
nyx_proc_init(pid_t pid);

void
nyx_proc_terminate(void);

void *
nyx_proc_start(void *state);

proc_stat_t *
proc_stat_new(pid_t pid, const char *name, watch_t *watch);

void
nyx_proc_remove(nyx_proc_t *proc, pid_t pid);

void
nyx_proc_add(nyx_proc_t *proc, pid_t pid, watch_t *watch);

void
nyx_proc_destroy(nyx_proc_t *proc);

sys_proc_stat_t *
sys_proc_new(void);

void
sys_proc_dump(sys_proc_stat_t *stat);

bool
sys_proc_read(sys_proc_stat_t *stat);

sys_info_t *
sys_info_new(void);

void
sys_info_dump(sys_info_t *sys);

bool
sys_info_read_proc(sys_info_t *sys, pid_t pid, int64_t page_size);

uint64_t
total_memory_size(void);

int64_t
get_page_size(void);

int32_t
num_cpus(void);

/* vim: set et sw=4 sts=4 tw=80: */
