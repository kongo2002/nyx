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

#ifndef __NYX_PROC_H__
#define __NYX_PROC_H__

#include "list.h"
#include "stack.h"

#include <stdlib.h>

typedef struct
{
    unsigned long user_time;        /* 14 */
    unsigned long system_time;      /* 15 */
    long child_user_time;           /* 16 */
    long child_system_time;         /* 17 */
    unsigned long long start_time;  /* 22 */
    unsigned long virtual_size;     /* 23 */
    long resident_set_size;         /* 24 */

    unsigned long long total_time;

} sys_info_t;

typedef struct
{
    pid_t pid;
    sys_info_t info;
    const char *name;
    double cpu_usage;
    long mem_usage;
} proc_stat_t;

typedef struct
{
    unsigned long long user_time;
    unsigned long long nice_time;
    unsigned long long system_time;
    unsigned long long idle_time;
    unsigned long long iowait_time;

    unsigned long long total;
    unsigned long long period;
} sys_proc_stat_t;

DECLARE_STACK(sys_proc_stat_t, sys_proc)

typedef struct
{
    unsigned long total_memory;
    long page_size;
    int num_cpus;
    sys_proc_stat_t sys_proc;
    list_t *processes;
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
proc_stat_new(pid_t pid, const char *name);

void
nyx_proc_remove(nyx_proc_t *proc, pid_t pid);

void
nyx_proc_add(nyx_proc_t *proc, pid_t pid, const char *name);

void
nyx_proc_destroy(nyx_proc_t *proc);

sys_proc_stat_t *
sys_proc_new(void);

void
sys_proc_dump(sys_proc_stat_t *stat);

int
sys_proc_read(sys_proc_stat_t *stat);

sys_info_t *
sys_info_new(void);

void
sys_info_dump(sys_info_t *sys);

int
sys_info_read_proc(sys_info_t *sys, pid_t pid);

unsigned long
total_memory_size(void);

long
get_page_size(void);

int
num_cpus(void);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
