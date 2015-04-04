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
#include "socket.h"
#include "utils.h"

#include <stdio.h>
#include <unistd.h>

#define PROC_STAT_STACK_SIZE 10
#define PROC_STAT_STACK_LIMIT 8

static volatile int need_exit = 0;

static void
proc_stat_destroy(void *obj)
{
    proc_stat_t *stat = obj;

    if (stat->mem_usage)
    {
        stack_long_destroy(stat->mem_usage);
        stat->mem_usage = NULL;
    }

    if (stat->cpu_usage)
    {
        stack_double_destroy(stat->cpu_usage);
        stat->cpu_usage = NULL;
    }

    free(stat);
}

nyx_proc_t *
nyx_proc_new(void)
{
    nyx_proc_t *proc = xcalloc1(sizeof(nyx_proc_t));

    proc->processes = list_new(proc_stat_destroy);
    proc->total_memory = total_memory_size();
    proc->page_size = get_page_size();
    proc->num_cpus = num_cpus();

    return proc;
}

proc_stat_t *
proc_stat_new(pid_t pid, const char *name, watch_t *watch)
{
    proc_stat_t *stat = xcalloc1(sizeof(proc_stat_t));

    stat->pid = pid;
    stat->name = name;
    stat->watch = watch;

    /* TODO: configurable stack size */
    stat->mem_usage = stack_long_new(PROC_STAT_STACK_SIZE);
    stat->cpu_usage = stack_double_new(PROC_STAT_STACK_SIZE);

    return stat;
}

static unsigned long long
calculate_sys_period(sys_proc_stat_t *stat)
{
    /* read current statistics */
    sys_proc_stat_t current;
    memset(&current, 0, sizeof(sys_proc_stat_t));

    if (!sys_proc_read(&current))
        return 0;

    /* calculate diff */
    current.period = current.total - stat->total;

    memcpy(stat, &current, sizeof(sys_proc_stat_t));

    return current.period;
}

static unsigned long long
calculate_proc_diff(proc_stat_t *proc, long page_size)
{
    unsigned long long diff = 0;

    /* read current process statistics */
    sys_info_t current;
    memset(&current, 0, sizeof(sys_info_t));

    if (!sys_info_read_proc(&current, proc->pid))
        return 0;

    /* correct mem_usage from 'number of pages' to 'in kilobytes' unit */
    if (current.resident_set_size)
        stack_long_add(proc->mem_usage, current.resident_set_size * page_size / 1024);

    /* calculate cpu diff/usage */
    diff = current.total_time - proc->info.total_time;

    memcpy(&proc->info, &current, sizeof(sys_info_t));

    return diff;
}

static void
calculate_proc_stats(proc_stat_t *stat, nyx_proc_t *sys, unsigned long long period)
{
    unsigned max = sys->num_cpus * 100;
    unsigned long long diff = 0;

    diff = calculate_proc_diff(stat, sys->page_size);

    if (period > 0)
    {
        double usage = ((double)diff) / period * max;
        stack_double_add(stat->cpu_usage, MAX(0, MIN(max, usage)));
    }
    else
        stack_double_add(stat->cpu_usage, 0);
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

    if (proc->page_size < 1)
    {
        log_error("Unable to determine page size");
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
    proc_stat_t *me = proc_stat_new(pid, "nyx", NULL);
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
nyx_proc_add(nyx_proc_t *proc, pid_t pid, watch_t *watch)
{
    proc_stat_t *stat = proc_stat_new(pid, watch->name, watch);

    list_add(proc->processes, stat);
}

void
nyx_proc_terminate(void)
{
    need_exit = 1;
}

static int
exceeds_cpu(double value, void *obj)
{
    proc_stat_t *proc = obj;

    return proc->watch && proc->watch->max_cpu && value >= proc->watch->max_cpu;
}

static int
exceeds_mem(unsigned long value, void *obj)
{
    proc_stat_t *proc = obj;

    return proc->watch && proc->watch->max_memory && value >= proc->watch->max_memory;
}

static int
proc_port_check(proc_stat_t *proc, nyx_t *nyx)
{
    watch_t *watch = proc->watch;

    if (!watch->port_check)
        return 1;

    if (!check_port(watch->port_check))
    {
        log_warn("Process '%s': port %u is not available",
                proc->name, watch->port_check);

        return nyx->proc->event_handler(PROC_PORT_NOT_OPEN, proc, nyx);
    }

    return 1;
}

static int
proc_http_check(proc_stat_t *proc, nyx_t *nyx)
{
    watch_t *watch = proc->watch;

    if (watch->http_check == NULL)
        return 1;

    if (!check_http(watch->http_check, watch->http_check_port, watch->http_check_method))
    {
        log_warn("Process '%s': HTTP check failed - %s %s",
                proc->name,
                http_method_to_string(watch->http_check_method),
                watch->http_check);

        return nyx->proc->event_handler(PROC_HTTP_CHECK_FAILED, proc, nyx);
    }

    return 1;
}

void *
nyx_proc_start(void *state)
{
    nyx_t *nyx = state;
    nyx_proc_t *sys = nyx->proc;

    unsigned interval = nyx->options.check_interval;

    log_debug("Starting proc watch - check interval %us", interval);

    /* reset need_exit in case of a restart */
    need_exit = 0;

    while (!need_exit)
    {
        unsigned long long period = calculate_sys_period(&sys->sys_proc);
        list_node_t *node = sys->processes->head;

        while (node)
        {
            proc_stat_t *proc = node->data;

            /* calculate process' statistics */
            calculate_proc_stats(proc, sys, period);

#ifndef NDEBUG
            long mem_usage = stack_long_newest(proc->mem_usage);
            double cpu_usage = stack_double_newest(proc->cpu_usage);

            unsigned long out_mem = 0;
            char unit = get_size_unit(mem_usage, &out_mem);

            log_debug("Process '%s' (%d): CPU %4.1f%% MEM (%lu%c) %5.2f%%",
                    proc->name, proc->pid, cpu_usage,
                    out_mem, unit,
                    ((double)mem_usage / sys->total_memory * 100.0));
#endif

            /* no event handler registered
             * -> nothing to be done anyways */
            int handle_events = sys->event_handler != NULL && proc->watch != NULL;

            /* handle CPU events? */
            if (handle_events &&
                    proc->watch->max_cpu &&
                    stack_double_satisfy(proc->cpu_usage, exceeds_cpu, proc) >= PROC_STAT_STACK_LIMIT)
            {
                log_warn("Process '%s' (%d) exceeds its CPU usage maximum of %u%%",
                        proc->name, proc->pid, proc->watch->max_cpu);

                handle_events = sys->event_handler(PROC_MAX_CPU, proc, nyx);
            }

            /* handle memory events? */
            if (handle_events &&
                    proc->watch->max_memory &&
                    stack_long_satisfy(proc->mem_usage, exceeds_mem, proc) >= PROC_STAT_STACK_LIMIT)
            {
                unsigned long bytes;
                char unit = get_size_unit(proc->watch->max_memory, &bytes);

                log_warn("Process '%s' (%d) exceeds its memory usage maximum of %ld%c",
                        proc->name, proc->pid, bytes, unit);

                handle_events = sys->event_handler(PROC_MAX_MEMORY, proc, nyx);
            }

            /* check port if specified */
            if (handle_events)
                handle_events = proc_port_check(proc, nyx);

            /* check HTTP endpoint if specified */
            if (handle_events)
                proc_http_check(proc, nyx);

            node = node->next;
        }

        wait_interval(interval);
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
    if (fscanf(proc, "%*8s %llu %llu %llu %llu %llu",
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

    if (fscanf(proc, "%*d %*256s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu"
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

long
get_page_size(void)
{
    long value = 0;

    if ((value = sysconf(_SC_PAGESIZE)) == -1)
    {
        log_perror("nyx: sysconf");
        return 0;
    }

    return value;
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

IMPLEMENT_STACK(unsigned long, long)
IMPLEMENT_STACK(double, double)

/* vim: set et sw=4 sts=4 tw=80: */
