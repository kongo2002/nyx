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
#include "proc.h"

#include <stdio.h>

nyx_proc_t *
nyx_proc_new(unsigned snapshots)
{
    nyx_proc_t *proc = xcalloc1(sizeof(nyx_proc_t));

    /* TODO: dispose func */
    proc->processes = hash_new(NULL);
    proc->total_memory = total_memory_size();
    proc->num_cpus = num_cpus();
    proc->sys_procs = stack_sys_proc_new(snapshots);

    return proc;
}

void
nyx_proc_destroy(nyx_proc_t *proc)
{
    hash_destroy(proc->processes);
    stack_sys_proc_destroy(proc->sys_procs);
    free(proc);
}

sys_proc_stat_t *
sys_proc_new(void)
{
    sys_proc_stat_t *stat = xcalloc1(sizeof(sys_proc_stat_t));

    return stat;
}

void
sys_proc_dump(sys_proc_stat_t *stat)
{
    log_info("System process info:");
    log_info("  User time:    %llu", stat->user_time);
    log_info("  Nice time:    %llu", stat->nice_time);
    log_info("  System time:  %llu", stat->system_time);
    log_info("  Idle time:    %llu", stat->idle_time);
    log_info("  IO wait time: %llu", stat->iowait_time);
}

int
sys_proc_read(sys_proc_stat_t *stat)
{
    FILE *proc = fopen("/proc/stat", "r");

    if (proc == NULL)
    {
        log_perror("nyx: fopen");
        return 0;
    }

    /* right now we are interested in the first line (cpu ...)
     * only which represents the overall cpu usage */
    if (fscanf(proc, "%*s %llu %llu %llu %llu %llu",
                &stat->user_time,
                &stat->nice_time,
                &stat->system_time,
                &stat->idle_time,
                &stat->iowait_time) != 5)
    {
        log_error("Failed to parse /proc/stat");
        fclose(proc);

        return 0;
    }

    fclose(proc);
    return 1;
}

sys_info_t *
sys_info_new(void)
{
    sys_info_t *sys = xcalloc1(sizeof(sys_info_t));

    return sys;
}

int
sys_info_read_proc(sys_info_t *sys, pid_t pid)
{
    char buffer[64] = {0};
    sprintf(buffer, "/proc/%d/stat", pid);
    FILE *proc = NULL;

    if ((proc = fopen(buffer, "r")) == NULL)
    {
        log_perror("nyx: fopen");
        return 0;
    }

    if (fscanf(proc, "%d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu"
               "%lu %ld %ld %*d %*d %*d %*d %*u %lu %ld",
               &sys->pid,
               &sys->user_time,
               &sys->system_time,
               &sys->child_user_time,
               &sys->child_user_time,
               &sys->virtual_size,
               &sys->resident_set_size) != 7)
    {
        log_error("Failed to parse %s", buffer);
        fclose(proc);

        return 0;
    }

    fclose(proc);
    return 1;
}

unsigned long
total_memory_size(void)
{
    unsigned long mem_size = 0;
    FILE *proc = fopen("/proc/meminfo", "r");

    if (proc == NULL)
    {
        log_perror("nyx: fopen");
        return 0;
    }

    if (fscanf(proc, "MemTotal: %lu kB", &mem_size) != 1)
    {
        log_error("Failed to parse /proc/meminfo");
        mem_size = 0;
    }

    fclose(proc);
    return mem_size;
}

int
num_cpus(void)
{
    int cpus = -1;
    FILE *proc = fopen("/proc/stat", "r");
    char buffer[256] = {0};

    if (proc == NULL)
    {
        log_perror("nyx: fopen");
        return 0;
    }

    while (fgets(buffer, 256, proc))
    {
        if (strstr(buffer, "cpu") != buffer)
            break;
        cpus++;
    }

    fclose(proc);
    return cpus;
}

void
sys_info_dump(sys_info_t *sys)
{
    log_info("Process info PID %d:", sys->pid);
    log_info("  User time:         %lu", sys->user_time);
    log_info("  System time:       %lu", sys->system_time);
    log_info("  Child user time:   %ld", sys->child_user_time);
    log_info("  Child system time: %ld", sys->child_system_time);
    log_info("  Virtual size:      %lu", sys->virtual_size);
    log_info("  Resident set:      %ld", sys->resident_set_size);
}

IMPLEMENT_STACK(sys_proc_stat_t, sys_proc)

/* vim: set et sw=4 sts=4 tw=80: */
