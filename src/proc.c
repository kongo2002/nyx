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

#include "def.h"
#include "log.h"
#include "proc.h"
#include "socket.h"
#include "utils.h"

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#define PROC_STAT_STACK_SIZE 10
#define PROC_STAT_STACK_LIMIT 8

static volatile bool need_exit = false;

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

static uint64_t
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

static uint64_t
calculate_proc_diff(proc_stat_t *proc, int64_t page_size)
{
    uint64_t diff = 0;

    /* read current process statistics */
    sys_info_t current;
    memset(&current, 0, sizeof(sys_info_t));

    if (!sys_info_read_proc(&current, proc->pid, page_size))
        return 0;

    if (current.resident_set_size)
        stack_long_add(proc->mem_usage, current.resident_set_size);

    /* calculate cpu diff/usage */
    diff = current.total_time - proc->info.total_time;

    memcpy(&proc->info, &current, sizeof(sys_info_t));

    return diff;
}

static void
calculate_proc_stats(proc_stat_t *stat, nyx_proc_t *sys, uint64_t period)
{
    uint32_t max = sys->num_cpus * 100;
    uint64_t diff = calculate_proc_diff(stat, sys->page_size);

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
    nyx_proc_t *proc = nyx_proc_new();

    /* validate some basic values */
    if (proc->total_memory < 1)
    {
        log_error("Unable to determine total memory size");
        nyx_proc_destroy(proc);

        return NULL;
    }
    else
    {
        log_debug("Total memory: %" PRIu64 " MB", proc->total_memory / 1024);
    }

    if (proc->num_cpus < 1)
    {
        log_error("Unable to determine number of CPUs");
        nyx_proc_destroy(proc);

        return NULL;
    }
    else
    {
        log_debug("Number of CPUs: %d", proc->num_cpus);
    }


    if (proc->page_size < 1)
    {
        log_error("Unable to determine page size");
        nyx_proc_destroy(proc);

        return NULL;
    }

    bool success = sys_proc_read(&proc->sys_proc);

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
    success = sys_info_read_proc(&me->info, me->pid, proc->page_size);

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

static bool
nyx_proc_exists(nyx_proc_t *proc, pid_t pid)
{
    if (!proc->processes)
        return false;

    list_node_t *node = proc->processes->head;

    while (node)
    {
        proc_stat_t *stat = node->data;

        if (stat->pid == pid)
            return true;

        node = node->next;
    }

    return false;
}

void
nyx_proc_add(nyx_proc_t *proc, pid_t pid, watch_t *watch)
{
    if (!nyx_proc_exists(proc, pid))
    {
        proc_stat_t *stat = proc_stat_new(pid, watch->name, watch);

        list_add(proc->processes, stat);
    }
}

void
nyx_proc_terminate(void)
{
    need_exit = true;
}

static bool
exceeds_cpu(double value, void *obj)
{
    proc_stat_t *proc = obj;

    return proc->watch && proc->watch->max_cpu && value >= proc->watch->max_cpu;
}

static bool
exceeds_mem(uint64_t value, void *obj)
{
    proc_stat_t *proc = obj;

    return proc->watch && proc->watch->max_memory && value >= proc->watch->max_memory;
}

static bool
proc_port_check(proc_stat_t *proc, nyx_t *nyx)
{
    watch_t *watch = proc->watch;

    if (!watch->port_check)
        return true;

    if (watch->port_check->host)
    {
        if (!check_port(watch->port_check->host, watch->port_check->port))
        {
            log_warn("Process '%s': %s:%u is not available",
                    proc->name, watch->port_check->host, watch->port_check->port);

            return nyx->proc->event_handler(PROC_PORT_NOT_OPEN, proc, nyx);
        }
    }
    else
    {
        if (!check_local_port(watch->port_check->port))
        {
            log_warn("Process '%s': port %u is not available",
                    proc->name, watch->port_check->port);

            return nyx->proc->event_handler(PROC_PORT_NOT_OPEN, proc, nyx);
        }
    }

    return true;
}

static bool
proc_http_check(proc_stat_t *proc, nyx_t *nyx)
{
    watch_t *watch = proc->watch;

    if (watch->http_check == NULL)
        return true;

    if (!check_http(watch->http_check, watch->http_check_port, watch->http_check_method))
    {
        log_warn("Process '%s': HTTP check failed - %s %s",
                proc->name,
                http_method_to_string(watch->http_check_method),
                watch->http_check);

        return nyx->proc->event_handler(PROC_HTTP_CHECK_FAILED, proc, nyx);
    }

    return true;
}

static void
handle_sigusr1(UNUSED int signum)
{
    log_debug("proc: caught SIGUSR1");

    nyx_proc_terminate();
}

static void
setup_proc_signals(void)
{
    struct sigaction action =
    {
        .sa_flags = SA_NOCLDSTOP | SA_RESTART,
        .sa_handler = handle_sigusr1
    };

    sigemptyset(&action.sa_mask);

    sigaction(SIGUSR1, &action, NULL);
}

void *
nyx_proc_start(void *state)
{
    nyx_t *nyx = state;
    nyx_proc_t *sys = nyx->proc;

    setup_proc_signals();

    uint32_t interval = nyx->options.check_interval;

    log_debug("Starting proc watch - check interval %us", interval);

    /* reset need_exit in case of a restart */
    need_exit = false;

    while (!need_exit)
    {
        uint64_t period = calculate_sys_period(&sys->sys_proc);
        list_node_t *node = sys->processes->head;

        while (node)
        {
            proc_stat_t *proc = node->data;

            /* calculate process' statistics */
            calculate_proc_stats(proc, sys, period);

#ifndef NDEBUG
            uint64_t mem_usage = stack_long_newest(proc->mem_usage);
            double cpu_usage = stack_double_newest(proc->cpu_usage);

            uint64_t out_mem = 0;
            char mem_unit = get_size_unit(mem_usage, &out_mem);

            log_debug("Process '%s' (%d): CPU %4.1f%% MEM (%" PRIu64 "%c) %5.2f%%",
                    proc->name, proc->pid, cpu_usage,
                    out_mem, mem_unit,
                    ((double)mem_usage / sys->total_memory * 100.0));
#endif

            /* no event handler registered
             * -> nothing to be done anyways */
            bool handle_events = sys->event_handler != NULL && proc->watch != NULL;

            /* handle CPU events? */
            if (handle_events &&
                    proc->watch->max_cpu &&
                    stack_double_satisfy(proc->cpu_usage, exceeds_cpu, proc) >= PROC_STAT_STACK_LIMIT)
            {
                log_warn("Process '%s' (%d) exceeds its CPU usage maximum of %u%%"
                         " in at least %d of the last %d tests",
                         proc->name, proc->pid, proc->watch->max_cpu,
                         PROC_STAT_STACK_LIMIT, PROC_STAT_STACK_SIZE);

                handle_events = sys->event_handler(PROC_MAX_CPU, proc, nyx);
            }

            /* handle memory events? */
            if (handle_events &&
                    proc->watch->max_memory &&
                    stack_long_satisfy(proc->mem_usage, exceeds_mem, proc) >= PROC_STAT_STACK_LIMIT)
            {
                uint64_t bytes;
                char unit = get_size_unit(proc->watch->max_memory, &bytes);

                log_warn("Process '%s' (%d) exceeds its memory usage maximum of %" PRIu64 "%c"
                         " in at least %d of the last %d tests",
                         proc->name, proc->pid, bytes, unit,
                         PROC_STAT_STACK_LIMIT, PROC_STAT_STACK_SIZE);

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
    log_info("  User time:    %" PRIu64, stat->user_time);
    log_info("  Nice time:    %" PRIu64, stat->nice_time);
    log_info("  System time:  %" PRIu64, stat->system_time);
    log_info("  Idle time:    %" PRIu64, stat->idle_time);
    log_info("  IO wait time: %" PRIu64, stat->iowait_time);
    log_info("  Total time:   %" PRIu64, stat->total);
}

#ifndef OSX
static bool
sys_proc_read_proc(sys_proc_stat_t *stat)
{
    FILE *proc = fopen("/proc/stat", "r");

    if (proc == NULL)
    {
        log_perror("nyx: fopen");
        return false;
    }

    /* right now we are interested in the first line (cpu ...)
     * only which represents the overall cpu usage */
    if (fscanf(proc, "%*8s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "",
                &stat->user_time,
                &stat->nice_time,
                &stat->system_time,
                &stat->idle_time,
                &stat->iowait_time) != 5)
    {
        log_error("Failed to parse /proc/stat");
        fclose(proc);

        return false;
    }

    /* calculate sum */
    stat->total =
        stat->user_time +
        stat->nice_time +
        stat->system_time +
        stat->idle_time +
        stat->iowait_time;

    fclose(proc);
    return true;
}
#else
#include <sys/resource.h>
#include <sys/mman.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_host.h>

static bool
sys_proc_read_osx(sys_proc_stat_t *stat)
{
    uint32_t cpu_count = 0;
    processor_info_array_t p;
    mach_msg_type_number_t info_size;

    if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &cpu_count, &p, &info_size) != 0)
        return false;

    processor_cpu_load_info_data_t *data = (processor_cpu_load_info_data_t *) p;
    stat->total = 0;

    for (uint32_t i = 0; i < cpu_count; i++)
    {
        /* states: 0: user, 1: system, 2: idle, 3: nice */
        for (uint32_t j = 0; j < CPU_STATE_MAX; j++)
        {
            stat->total += data[i].cpu_ticks[j];
        }
    }

    /* correct total system ticks in respect
     * to the process load */
    stat->total *= 10000000;

    /* free resources */
    vm_deallocate(mach_task_self(), (vm_address_t)p, sizeof(integer_t) * info_size);

    return true;
}
#endif

bool
sys_proc_read(sys_proc_stat_t *stat)
{
#ifndef OSX
    return sys_proc_read_proc(stat);
#else
    return sys_proc_read_osx(stat);
#endif
}

sys_info_t *
sys_info_new(void)
{
    sys_info_t *sys = xcalloc1(sizeof(sys_info_t));

    return sys;
}

#ifndef OSX
bool
sys_info_read_proc(sys_info_t *sys, pid_t pid, int64_t page_size)
{
    char buffer[64] = {0};
    sprintf(buffer, "/proc/%d/stat", pid);
    FILE *proc = NULL;

    if ((proc = fopen(buffer, "r")) == NULL)
    {
        log_perror("nyx: fopen");
        return false;
    }

    if (fscanf(proc, "%*d %*256s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %" PRIu64
               "%" PRIu64 " %" PRId64 " %" PRId64 " %*d %*d %*d %*d %*u %" PRIu64 " %" PRId64,
               &sys->user_time,
               &sys->system_time,
               &sys->child_user_time,
               &sys->child_system_time,
               &sys->virtual_size,
               &sys->resident_set_size) != 6)
    {
        log_error("Failed to parse %s", buffer);
        fclose(proc);

        return false;
    }

    /* correct RSS from 'number of pages' to 'in kilobytes' unit */
    sys->resident_set_size *= page_size / 1024;

    sys->total_time = sys->user_time +
        sys->system_time +
        sys->child_user_time +
        sys->child_system_time;

    fclose(proc);
    return true;
}
#else
bool
sys_info_read_proc(sys_info_t *sys, pid_t pid, UNUSED int64_t page_size)
{
    struct proc_taskinfo pti;

    size_t pti_size = sizeof(pti);
    size_t result = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &pti, pti_size);
    if (result != pti_size)
        return false;

    sys->user_time = pti.pti_total_user;
    sys->system_time = pti.pti_total_system;
    sys->total_time = sys->user_time + sys->system_time;

    sys->virtual_size = pti.pti_virtual_size;
    sys->resident_set_size = pti.pti_resident_size / 1024;

    return true;
}
#endif

int64_t
get_page_size(void)
{
    int64_t value = 0;

    if ((value = sysconf(_SC_PAGESIZE)) == -1)
    {
        log_perror("nyx: sysconf");
        return 0;
    }

    return value;
}

static uint64_t
total_memory_size_sysconf(void)
{
#if defined(_SC_PAGESIZE) && defined(_SC_PHYS_PAGES)
    int64_t page_size = get_page_size();
    int64_t pages = sysconf(_SC_PHYS_PAGES);

    if (page_size > 0L && pages > 0L)
        return page_size * pages / 1024;
#endif

    return 0L;
}

static uint64_t
total_memory_size_proc(void)
{
    uint64_t mem_size = 0;

#ifndef OSX
    FILE *proc = fopen("/proc/meminfo", "r");

    if (proc == NULL)
    {
        log_perror("nyx: fopen");
        return 0;
    }

    if (fscanf(proc, "MemTotal: %" PRIu64 " kB", &mem_size) != 1)
    {
        log_error("Failed to parse /proc/meminfo");
        mem_size = 0;
    }

    fclose(proc);
#endif

    return mem_size;
}

uint64_t
total_memory_size(void)
{
    uint64_t mem_size = total_memory_size_proc();

    if (mem_size < 1L)
        return total_memory_size_sysconf();

    return mem_size;
}

static int32_t
num_cpus_proc(void)
{
    int32_t cpus = -1;

#ifndef OSX
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
#endif

    return cpus;
}

static int32_t
num_cpus_sysconf(void)
{
    int32_t cpus = 0;

#if defined(_SC_NPROCESSORS_ONLN)
    cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (cpus == -1)
    {
        log_perror("nyx: sysconf");
        return 0;
    }
#endif

    return cpus;
}

int32_t
num_cpus(void)
{
    int32_t cpus = num_cpus_proc();

    if (cpus < 1)
        return num_cpus_sysconf();

    return cpus;
}

void
sys_info_dump(sys_info_t *sys)
{
    log_info("Process info:");
    log_info("  User time:         %" PRIu64, sys->user_time);
    log_info("  System time:       %" PRIu64, sys->system_time);
    log_info("  Child user time:   %" PRId64, sys->child_user_time);
    log_info("  Child system time: %" PRId64, sys->child_system_time);
    log_info("  Virtual size:      %" PRIu64, sys->virtual_size);
    log_info("  Resident set:      %" PRId64, sys->resident_set_size);
    log_info("  Total time:        %" PRIu64, sys->total_time);
}

IMPLEMENT_STACK(uint64_t, long)
IMPLEMENT_STACK(double, double)

/* vim: set et sw=4 sts=4 tw=80: */
