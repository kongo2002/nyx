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
#include <unistd.h>

static volatile int need_exit = 0;

nyx_proc_t *
nyx_proc_new(void)
{
    nyx_proc_t *proc = xcalloc1(sizeof(nyx_proc_t));

    /* TODO: dispose func */
    proc->processes = list_new(free);
    proc->total_memory = total_memory_size();
    proc->num_cpus = num_cpus();

    return proc;
}

proc_stat_t *
proc_stat_new(pid_t pid, const char *name)
{
    proc_stat_t *stat = xcalloc1(sizeof(proc_stat_t));

    stat->pid = pid;
    stat->name = name;

    return stat;
}

static unsigned long long
calculate_sys_period(sys_proc_stat_t *stat)
{
    /* read current statistics */
    sys_proc_stat_t current;

    if (!sys_proc_read(&current))
        return 0;

    /* calculate diff */
    current.period = current.total - stat->total;

    memcpy(stat, &current, sizeof(sys_proc_stat_t));

    return current.period;
}

static unsigned long long
calculate_proc_diff(proc_stat_t *proc)
{
    unsigned long long diff = 0;

    /* read current process statistics */
    sys_info_t current;
    memset(&current, 0, sizeof(sys_info_t));

    if (!sys_info_read_proc(&current, proc->pid))
        return 0;

    /* calculate diff */
    diff = current.total_time - proc->info.total_time;

    memcpy(&proc->info, &current, sizeof(sys_info_t));

    return diff;
}

static void
calculate_proc_cpu_usage(proc_stat_t *stat, nyx_proc_t *sys, unsigned long long period)
{
    unsigned max = sys->num_cpus * 100;
    unsigned long long diff = 0;

    diff = calculate_proc_diff(stat);

    if (period > 0)
        stat->cpu_usage = MAX(0, MIN(max, ((double)diff) / period * max));
    else
        stat->cpu_usage = 0;
}

nyx_proc_t *
nyx_proc_init(pid_t pid)
{
    int success = 0;
    nyx_proc_t *proc = nyx_proc_new();

    /* validate some basic values */
    if (proc->total_memory < 1)
    {
        log_error("Unable to determine total memory size");
        nyx_proc_destroy(proc);

        return NULL;
    }

    if (proc->num_cpus < 1)
    {
        log_error("Unable to determine number of CPUs");
        nyx_proc_destroy(proc);

        return NULL;
    }

    success = sys_proc_read(&proc->sys_proc);

    if (!success)
    {
        log_error("Failed to read system statistics");
        nyx_proc_destroy(proc);

        return NULL;
    }

    /* add myself to watched processes */
    proc_stat_t *me = proc_stat_new(pid, "nyx");
    list_add(proc->processes, me);

    /* get current nyx process statistics */
    success = sys_info_read_proc(&me->info, me->pid);

    if (!success)
    {
        log_error("Failed to read process statistics of nyx");
        nyx_proc_destroy(proc);

        return NULL;
    }

    /* sleep for at least 100 ms */
    usleep(100000);

    return proc;
}

void
nyx_proc_remove(nyx_proc_t *proc, pid_t pid)
{
    list_node_t *node = proc->processes->head;

    while (node)
    {
        proc_stat_t *stat = node->data;

        if (stat->pid == pid)
        {
            list_remove(proc->processes, node);
            break;
        }

        node = node->next;
    }
}

void
nyx_proc_add(nyx_proc_t *proc, pid_t pid, const char *name)
{
    proc_stat_t *stat = proc_stat_new(pid, name);

    list_add(proc->processes, stat);
}

void
nyx_proc_terminate(void)
{
    need_exit = 1;
}

void *
nyx_proc_start(void *state)
{
    nyx_proc_t *sys = state;

    log_debug("Starting proc watch");

    while (!need_exit)
    {
        unsigned long long period = calculate_sys_period(&sys->sys_proc);
        list_node_t *node = sys->processes->head;

        while (node)
        {
            proc_stat_t *proc = node->data;

            calculate_proc_cpu_usage(proc, sys, period);

            log_debug("Process '%s' (%d): CPU %4.1f",
                    proc->name, proc->pid, proc->cpu_usage);

            node = node->next;
        }

        sleep(1);
    }

    log_debug("Stopped proc watch");

    return NULL;
}

void
nyx_proc_destroy(nyx_proc_t *proc)
{
    list_destroy(proc->processes);
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
    log_info("  Total time:   %llu", stat->total);
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

    /* calculate sum */
    stat->total =
        stat->user_time +
        stat->nice_time +
        stat->system_time +
        stat->idle_time +
        stat->iowait_time;

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

    if (fscanf(proc, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu"
               "%lu %ld %ld %*d %*d %*d %*d %*u %lu %ld",
               &sys->user_time,
               &sys->system_time,
               &sys->child_user_time,
               &sys->child_user_time,
               &sys->virtual_size,
               &sys->resident_set_size) != 6)
    {
        log_error("Failed to parse %s", buffer);
        fclose(proc);

        return 0;
    }

    sys->total_time = sys->user_time +
        sys->system_time +
        sys->child_user_time +
        sys->child_system_time;

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
    log_info("Process info:");
    log_info("  User time:         %lu", sys->user_time);
    log_info("  System time:       %lu", sys->system_time);
    log_info("  Child user time:   %ld", sys->child_user_time);
    log_info("  Child system time: %ld", sys->child_system_time);
    log_info("  Virtual size:      %lu", sys->virtual_size);
    log_info("  Resident set:      %ld", sys->resident_set_size);
    log_info("  Total time:        %llu", sys->total_time);
}

IMPLEMENT_STACK(sys_proc_stat_t, sys_proc)

/* vim: set et sw=4 sts=4 tw=80: */
