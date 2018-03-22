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

#define _GNU_SOURCE

#include "def.h"
#include "log.h"
#include "forker.h"
#include "fs.h"
#include "process.h"
#include "state.h"

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NYX_STATE_JOIN_TIMEOUT 30
#define NYX_MAX_FLAPPING_DELAY 600
#define NYX_FLAPPING_INTERVAL  60
#define NYX_FLAPPING_COUNT     5

typedef bool (*transition_func_t)(state_t *, state_e, state_e);

typedef struct
{
    state_e value;
    bool is_command;
} state_entry_t;

#ifndef NDEBUG
static const char *state_to_str[] =
{
    "STATE_INIT",
    "STATE_UNMONITORED",
    "STATE_STARTING",
    "STATE_RUNNING",
    "STATE_STOPPING",
    "STATE_STOPPED",
    "STATE_RESTARTING",
    "STATE_QUIT",
    "STATE_SIZE"
};

static const char *
state_to_string(state_e state)
{
    return state_to_str[state];
}

static const char *
state_idx_to_string(int32_t state)
{
    return state_to_str[state];
}
#endif

static const char *state_to_human_str[] =
{
    "initialized",
    "not monitored",
    "starting",
    "running",
    "stopping",
    "stopped",
    "restarting",
    "quit"
    ""
};

const char *
state_to_human_string(state_e state)
{
    return state_to_human_str[state];
}

static state_entry_t *
state_entry_new(state_e value, bool is_command)
{
    state_entry_t *entry = xcalloc1(sizeof(state_entry_t));

    entry->value = value;
    entry->is_command = is_command;

    return entry;
}

static bool
set_state_internal(state_t *state, state_e value, bool is_command)
{
    if (sem_wait(state->states_sem) != 0)
    {
        return false;
    }

    /* do not override QUIT signal */
    if (state->state == STATE_QUIT)
    {
        log_debug("state %s is about to quit - skip setting updated state",
                state->watch->name);

        sem_post(state->states_sem);
        sem_post(state->notify_sem);
        return false;
    }

    /* we don't set the state immediately but rather put
     * the 'requested' state into the states queue for the
     * state-loop to process those one after the other */
    state_entry_t *entry = state_entry_new(value, is_command);
    list_add(state->states, entry);

    /* release states semaphore */
    sem_post(state->states_sem);

    /* trigger state change notification */
    sem_post(state->notify_sem);

    return true;
}

/**
 * Try to set the state's state to the given value
 *
 * This function is guarded by the state's semaphore
 * meaning this function will wait until the lock
 * is acquired.
 */
bool
set_state(state_t *state, state_e value)
{
    return set_state_internal(state, value, false);
}

/**
 * Try to set the state's state to the given value.
 * This state is based on a user's command.
 *
 * This function is guarded by the state's semaphore
 * meaning this function will wait until the lock
 * is acquired.
 */
bool
set_state_command(state_t *state, state_e value)
{
    return set_state_internal(state, value, true);
}

#define DEBUG_LOG_STATE_FUNC \
    log_debug("State transition function of watch '%s'" \
              " from %s to %s",\
              state->watch->name,\
              state_to_string(from),\
              state_to_string(to))

static bool
to_unmonitored(state_t *state, state_e from, state_e to)
{
    bool is_running = false;
    watch_t *watch = state->watch;
    pid_t pid = state->pid;

    DEBUG_LOG_STATE_FUNC;

    /* determine if the process is already/still running */

    /* no pid yet
     * this should be usually the case on startup */
    if (pid < 1)
    {
        /* try to read pid from an existing pid file */
        pid = determine_pid(watch->name, state->nyx);
    }

    if (pid > 0)
    {
        is_running = check_process_running(pid);

        if (!is_running)
            clear_pid(watch->name, state->nyx);

        state->pid = is_running ? pid : 0;
    }

    set_state(state, is_running
        ? STATE_RUNNING
        : STATE_STOPPED);

    return true;
}

static bool
stop(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    nyx_t *nyx = state->nyx;
    watch_t *watch = state->watch;
    pid_t pid = state->pid;

    uint32_t times = nyx->options.def_stop_timeout;

    if (watch->stop_timeout)
        times = watch->stop_timeout;

    /* nothing to do */
    if (state->state == STATE_STOPPED)
        return true;

    /* nothing to stop */
    if (pid < 1)
    {
        /* the process is obviously already stopped */
        set_state(state, STATE_STOPPED);
        return true;
    }

    /* in case a custom stop command is specified we use that one */
    if (watch->stop)
    {
        fork_info_t *stop_info = forker_stop(state->watch->id);

        if (write(nyx->forker_pipe, stop_info, sizeof(fork_info_t)) == -1)
            log_perror("nyx: write");

        free(stop_info);
    }
    /* otherwise we try SIGTERM */
    else
    {
        if (kill(pid, SIGTERM) == -1)
        {
            /* process does not exist
             * -> already terminated */
            if (errno == ESRCH)
                return true;

            log_perror("nyx: kill");
            return false;
        }
    }

    while (times-- > 0)
    {
        if (kill(pid, 0) == -1)
        {
            if (errno == ESRCH)
                goto end;
        }

        sleep(1);
    }

    /* the app failed to terminate after several attempts
     * -> send a SIGKILL now */

    if (kill(pid, SIGKILL) == -1 && errno != ESRCH)
    {
        log_perror("nyx: kill");
    }

    log_warn("Failed to stop watch '%s' after waiting %d seconds - "
             "sending SIGKILL now",
             watch->name,
             (watch->stop_timeout ? watch->stop_timeout : nyx->options.def_stop_timeout));

end:
    return true;
}

static bool
restart(state_t *state, state_e from, state_e to)
{
    log_info("Watch '%s' is restarting (PID %d)", state->watch->name, state->pid);

    return stop(state, from, to);
}


static pid_t
start_state(state_t *state)
{
    /* start program via forker */
    fork_info_t *start_info = forker_start(state->watch->id);

    if (write(state->nyx->forker_pipe, start_info, sizeof(fork_info_t)) == -1)
        log_perror("nyx: write");

    free(start_info);

    /* let's check if the process is running at all
     * we will delay a little bit to give the process some
     * time to launch 'execvp' */
    usleep(500000);

    pid_t pid = determine_pid(state->watch->name, state->nyx);

    if (pid)
    {
        if (!check_process_running(pid))
        {
            log_debug("Watch '%s' failed to start", state->watch->name);
            return 0;
        }

        state->pid = pid;

        log_debug("Retrieved PID %d for watch '%s'", pid, state->watch->name);
    }

    return pid;
}

static bool
start(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (start_state(state) > 0)
        set_state(state, STATE_RUNNING);
    else
        set_state(state, STATE_STOPPED);

    return true;
}

static bool
state_is_running(int32_t state)
{
    return state == STATE_RUNNING;
}

static uint32_t
was_running_for(state_t *state)
{
    /* search for the latest 'RUNNING' event */
    time_t last_running = timestack_find_latest(state->history, state_is_running);

    if (last_running > 0)
    {
        time_t now_time = time(NULL);
        time_t running_for = now_time - last_running;

        return running_for;
    }

    return 0;
}

static bool
stopped(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    /* restart if the stop wasn't requested via 'STOPPING' */
    if (from != STATE_STOPPING && from != STATE_STOPPED)
        set_state(state, STATE_STARTING);

    /* reset failed counter in case the watch was running
     * for the maximum flapping time */
    if (was_running_for(state) > (NYX_FLAPPING_INTERVAL / NYX_FLAPPING_COUNT))
        state->failed_counter = 0;

    if (from != STATE_UNMONITORED)
        log_info("Watch '%s' just stopped", state->watch->name);

    return true;
}

static bool
running(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (state->nyx->proc && state->pid)
        nyx_proc_add(state->nyx->proc, state->pid, state->watch);

    bool is_init = from == STATE_UNMONITORED || from == STATE_INIT;

    log_info("Watch '%s' is %s running (PID %d)",
            state->watch->name,
            (is_init ? "still" : "now"),
            state->pid);

    return true;
}

#undef DEBUG_LOG_STATE_FUNC

static transition_func_t transition_table[STATE_SIZE][STATE_SIZE] =
{
    /* INIT, UNMONITORED,   STARTING, RUNNING, STOPPING, STOPPED, RESTARTING, QUIT */

    /* INIT to ... */
    { NULL, to_unmonitored, NULL,     running, NULL,     stopped, NULL },

    /* UNMONITORED to ... */
    { NULL, NULL,           start,    running, stop,     stopped, NULL },
    /* STARTING to ... */
    { NULL, to_unmonitored, NULL,     running, stop,     stopped, NULL },
    /* RUNNING to ... */
    { NULL, to_unmonitored, NULL,     NULL,    stop,     stopped, restart },
    /* STOPPING to ... */
    { NULL, to_unmonitored, NULL,     NULL,    stop,     stopped, NULL },
    /* STOPPED to ... */
    { NULL, to_unmonitored, start,    running, NULL,     stopped, start },
    /* RESTARTING to ... */
    { NULL, to_unmonitored, NULL,     running, stop,     start,   NULL },

    /* QUIT to ... */
    { NULL }
};

static state_t*
find_state_by_pid(list_t *states, pid_t pid)
{
    if (states == NULL)
        return NULL;

    list_node_t *node = states->head;

    while (node)
    {
        state_t *state = node->data;

        if (state != NULL && state->pid == pid)
            return state;

        node = node->next;
    }

    return NULL;
}

bool
dispatch_event(pid_t pid, process_event_data_t *event_data, nyx_t *nyx)
{
    state_t *state = NULL;

    log_debug("Incoming event data for PID %d", pid);

    switch (event_data->type)
    {
        case EVENT_EXIT:
            if (nyx->proc)
                nyx_proc_remove(nyx->proc, pid);

            state = find_state_by_pid(nyx->states, pid);

            if (state != NULL)
            {
                set_state(state, STATE_STOPPED);

                state->pid = 0;
                clear_pid(state->watch->name, nyx);
            }
            break;
        case EVENT_FORK:
        default:
            /* do nothing for now */
            break;
    }

    return true;
}

bool
dispatch_poll_result(pid_t pid, bool is_running, nyx_t *nyx)
{
    log_debug("Incoming polling data for PID %d: running: %s",
            pid, (is_running ? "true" : "false"));

    state_t *state = find_state_by_pid(nyx->states, pid);

    if (state != NULL)
    {
        state_e next_state = is_running ? STATE_RUNNING : STATE_STOPPED;

        if (!is_running)
        {
            /* TODO: secure this one by semaphore as well? */
            state->pid = 0;
            clear_pid(state->watch->name, nyx);

            if (nyx->proc)
                nyx_proc_remove(nyx->proc, pid);
        }

        set_state(state, next_state);
    }

    return true;
}

#ifdef OSX
static char *
named_semaphore_name(watch_t *watch, uint32_t idx)
{
    size_t sem_name_len = strlen(watch->name) + 4;
    char *sem_name = xcalloc(sem_name_len, sizeof(char));

    snprintf(sem_name, sem_name_len, "%s_%u", watch->name, idx);

    return sem_name;
}

static sem_t *
init_named_semaphore(watch_t *watch, uint32_t idx)
{
    sem_t *semaphore = NULL;
    char *sem_name = named_semaphore_name(watch, idx);

    log_debug("Trying to create a new named semaphore (%s) for watch %s [%u]",
            sem_name, watch->name, idx);

    /* initialize a named-semaphore as OSX does not support unnamed ones
     * - chmod of the semaphore (0644)
     * - initially unlocked (= 1) */
    semaphore = sem_open(sem_name, O_CREAT | O_EXCL, 0644, 1);

    if (semaphore == SEM_FAILED)
    {
        log_debug("Semaphore (%s) already exists - trying to unlink", sem_name);

        /* the semaphore should not exist beforehand ->
         * try to remove and retry -> then fail */
        int32_t err = sem_unlink(sem_name);
        if (err == 0)
        {
            log_debug("Try to create semaphore (%s) again", sem_name);

            /* remove succeeded -> try again */
            semaphore = sem_open(sem_name, O_CREAT | O_EXCL, 0644, 1);
        }
        else
            log_critical_perror("nyx: sem_unlink");
    }

    if (semaphore == SEM_FAILED)
        log_critical_perror("nyx: sem_open");

    free(sem_name);

    return semaphore;
}

static void
remove_named_semaphore(watch_t *watch, sem_t *sem, uint32_t idx)
{
    char *sem_name = named_semaphore_name(watch, idx);

    sem_close(sem);
    sem_unlink(sem_name);

    free(sem_name);
}
#endif

state_t *
state_new(watch_t *watch, nyx_t *nyx)
{
    sem_t *states_semaphore = NULL, *notify_semaphore = NULL;
    state_t *state = xcalloc1(sizeof(state_t));

    state->nyx = nyx;
    state->watch = watch;
    state->state = STATE_UNMONITORED;
    state->history = timestack_new(MAX(nyx->options.history_size, 20));

    /* initialize states queue and populate with
     * 'initial' state of UNMONITORED */
    state->states = list_new(free);
    list_add(state->states, state_entry_new(STATE_UNMONITORED, false));

#ifndef OSX
    /* initialize unnamed semaphore
     * - process-local semaphore
     * - initially unlocked (= 1) */
    states_semaphore = xcalloc1(sizeof(sem_t));
    notify_semaphore = xcalloc1(sizeof(sem_t));

    int32_t init = sem_init(states_semaphore, 0, 1);

    if (init == -1)
        log_critical_perror("nyx: sem_init");

    init = sem_init(notify_semaphore, 0, 1);

    if (init == -1)
        log_critical_perror("nyx: sem_init");
#else
    /* on OSX we have to create named semaphores
     * that's why we create two semaphores with the
     * names: '<watch-name>_1' and '<watch-name>_2' */
    states_semaphore = init_named_semaphore(watch, 1);
    notify_semaphore = init_named_semaphore(watch, 2);
#endif

    state->states_sem = states_semaphore;
    state->notify_sem = notify_semaphore;

    return state;
}

void
state_destroy(state_t *state)
{
    if (state->thread != NULL)
    {
        int32_t join = 0, join_timeout = MAX(NYX_STATE_JOIN_TIMEOUT, state->watch->stop_timeout);
        const char *name = state->watch->name;

#ifndef OSX
        time_t now = time(NULL);

        const struct timespec timeout =
        {
            .tv_sec = now + join_timeout,
            .tv_nsec = 0
        };
#endif

        log_debug("Waiting for state thread of watch '%s' to terminate", name);

        /* join thread */
        join =
#ifndef OSX
            pthread_timedjoin_np(*state->thread, NULL, &timeout);
#else
            pthread_join(*state->thread, NULL);
#endif

        if (join != 0)
        {
            if (errno == ETIMEDOUT)
            {
                log_error("State thread of watch '%s' failed to terminate "
                          "after waiting %ds", name, join_timeout);
            }

            log_error("Joining of state thread of watch '%s' failed: %d",
                    state->watch->name, join);
        }

        free(state->thread);
    }

    /* notify semaphore */
    if (state->notify_sem != NULL)
    {
#ifndef OSX
        sem_destroy(state->notify_sem);
        free(state->notify_sem);
#else
        remove_named_semaphore(state->watch, notify_sem, 2);
#endif
    }

    /* states semaphore */
    if (state->states_sem != NULL)
    {
#ifndef OSX
        sem_destroy(state->states_sem);
        free(state->states_sem);
#else
        remove_named_semaphore(state->watch, state->states_sem, 1);
#endif
    }

    if (state->history)
    {
        timestack_destroy(state->history);
        state->history = NULL;
    }

    list_destroy(state->states);

    free(state);
}

static bool
process_state(state_t *state, state_e old_state, state_e new_state)
{
    log_debug("Watch '%s' (PID %d): %s -> %s",
            state->watch->name,
            state->pid,
            state_to_string(old_state),
            state_to_string(new_state));

    transition_func_t func = transition_table[old_state][new_state];

    /* no handler for the given state transition
     * meaning the transition is not allowed */
    if (func == NULL)
    {
        log_debug("Transition from %s to %s is not valid",
                state_to_string(old_state),
                state_to_string(new_state));

        return false;
    }

    bool result = func(state, old_state, new_state);

    if (!result)
    {
        log_warn("Processing state of watch '%s' failed (PID %d)",
                state->watch->name, state->pid);
    }
#ifdef USE_PLUGINS
    else
    {
        notify_state_change(state->nyx->plugins,
                state->watch->name, state->pid, new_state);
    }
#endif

    return result;
}

static bool
is_flapping(state_t *state, uint32_t changes, int32_t within)
{
    uint32_t i = 0, is_stopped = 0, started = 0;
    timestack_t *hist = state->history;
    timestack_elem_t *elem = hist->elements;

    if (hist->count < (changes * 2))
        return false;

    time_t now_time = time(NULL);

    while (i++ < hist->count)
    {
        state_e value = elem->value;

        /* we are interested in counting 'starting' and 'stopped'
         * events only */
        if (value != STATE_STARTING && value != STATE_STOPPED)
        {
            elem++;
            continue;
        }

        time_t seconds_ago = now_time - elem->time;

        /* we are interested in events that happened in the
         * last 'within' seconds only */
        if (seconds_ago > within)
            return false;

        if (value == STATE_STARTING)
            started++;
        else if (value == STATE_STOPPED)
            is_stopped++;

        if (started > changes && is_stopped > changes)
            return true;

        elem++;
    }

    return false;
}

static bool
is_command(void *data)
{
    state_entry_t *entry = data;

    return entry->is_command;
}

static void
safe_sleep(state_t *state, uint32_t seconds)
{
    while (seconds-- > 0 && state->state != STATE_QUIT)
    {
        /* the 'sleep' may be interrupted by a user-command
         * i.e. STARTING, STOPPING, RESTARTING or QUIT */

        if (sem_wait(state->states_sem) != 0)
            break;

        void *command_found = list_find(state->states, is_command);

        sem_post(state->states_sem);

        if (command_found)
            break;

        sleep(1);
    }
}

void
state_loop(state_t *state)
{
    int32_t sem_fail = 0;

    watch_t *watch = state->watch;
    state_e last_state = STATE_INIT;

    log_debug("Starting state loop for watch '%s'", watch->name);

    /* wait until the event manager triggers this
     * state semaphore */
    while ((sem_fail = sem_wait(state->notify_sem)) == 0)
    {
        state_e current_state;

        /* QUIT is handled immediately */
        if (state->state == STATE_QUIT)
        {
            log_info("Watch '%s' terminating", watch->name);
            break;
        }

        /* acquire states semaphore */
        if ((sem_fail = sem_wait(state->states_sem) != 0))
            break;

        /* check if there is a new state in the queue at all */
        state_entry_t *state_entry = NULL;
        bool state_exists = list_pop(state->states, (void *)&state_entry);

        /* release states semaphore immediately after popping the
         * first element (if set) */
        sem_post(state->states_sem);

        /* no new state found -> continue */
        if (!state_exists || state_entry == NULL)
            continue;

        /* free popped state entry as early as possible */
        current_state = state_entry->value;
        free(state_entry);
        state_entry = NULL;

        /* QUIT is handled immediately */
        if (current_state == STATE_QUIT)
        {
            log_info("Watch '%s' terminating", watch->name);
            break;
        }

        bool result = process_state(state, last_state, current_state);

        if (result)
        {
            if (last_state != current_state)
            {
                timestack_add(state->history, current_state);

#ifndef NDEBUG
                timestack_dump(state->history, state_idx_to_string);
#endif
            }

            /* the state might have been set to 'QUIT' during our
             * process_state step - let's quit now instead of waiting
             * one more iteration */
            if (state->state == STATE_QUIT)
            {
                log_info("Watch '%s' terminating", watch->name);
                break;
            }

            /* the state transition succeeded ->
             * set updated state now */
            state->state = current_state;
        }

        /* check for flapping processes
         * meaning 5 start/stop events within 60 seconds
         * TODO: configurable */
        if (current_state == STATE_STOPPED &&
                is_flapping(state, NYX_FLAPPING_COUNT, NYX_FLAPPING_INTERVAL))
        {
            /* increase the delayed time from 5 seconds to 10 minutes at max */
            uint32_t to_delay_max = 5.0 * pow(2.0, state->failed_counter);
            uint32_t to_delay = MIN(to_delay_max, NYX_MAX_FLAPPING_DELAY);

            state->failed_counter = MIN(state->failed_counter + 1, 10);

            log_warn("Watch '%s' appears to be flapping - delay for %u seconds. "
                     "Probably the start command is not executable or does "
                     "not exist at all.",
                     watch->name, to_delay);

            /* TODO: use select instead */
            safe_sleep(state, to_delay);
        }

        if (result)
            last_state = current_state;

        log_debug("Waiting on next state update for watch '%s'", watch->name);
    }

    if (sem_fail)
        log_perror("nyx: sem_wait");
}

void *
state_loop_start(void *data)
{
    state_t *state = data;

    state_loop(state);

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
