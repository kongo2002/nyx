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
#include "fs.h"
#include "log.h"
#include "process.h"
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*transition_func_t)(state_t *, state_e, state_e);

static const char *state_to_str[] =
{
    "STATE_INIT",
    "STATE_UNMONITORED",
    "STATE_STARTING",
    "STATE_RUNNING",
    "STATE_STOPPING",
    "STATE_STOPPED",
    "STATE_SIZE"
};

const char *
state_to_string(state_e state)
{
    return state_to_str[state];
}

void
set_state(state_t *state, state_e value)
{
    state->state = value;
    sem_post(state->sem);
}

#define DEBUG_LOG_STATE_FUNC \
    log_debug("State transition function of watch '%s'" \
              " from %s to %s",\
              state->watch->name,\
              state_to_string(from),\
              state_to_string(to))

static int
to_unmonitored(state_t *state, state_e from, state_e to)
{
    int running = 0;
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
        running = check_process_running(pid);

        if (!running)
            clear_pid(watch->name, state->nyx);

        state->pid = running ? pid : 0;
    }

    set_state(state, running
        ? STATE_RUNNING
        : STATE_STOPPED);

    return 1;
}

static int
stop(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    nyx_t *nyx = state->nyx;
    int times = nyx->options.def_grace;
    pid_t pid = state->pid;

    /* nothing to do */
    if (state->state == STATE_STOPPED)
        return 1;

    /* nothing to stop */
    if (pid < 1)
        return 1;

    /* first we try SIGTERM */
    if (kill(pid, SIGTERM) == -1)
    {
        /* process does not exist
         * -> already terminated */
        if (errno == ESRCH)
            return 1;

        log_perror("nyx: kill");
        return 0;
    }

    while (times-- > 0)
    {
        if (kill(pid, 0) == -1)
        {
            if (errno == ESRCH)
                return 1;
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
             state->watch->name,
             nyx->options.def_grace);

    return 1;
}

static void
set_environment(const watch_t *watch)
{
    const char *key = NULL;
    void *data = NULL;

    if (watch->env == NULL || hash_count(watch->env) < 1)
        return;

    hash_iter_t *iter = hash_iter_start(watch->env);

    while (hash_iter(iter, &key, &data))
    {
        char *value = data;

        if (setenv(key, value, 1) == -1)
            log_perror("nyx: setenv");
    }

    free(iter);
}

static void
close_fds(void)
{
    int fd, max;

    /* determine maximum */
    if ((max = getdtablesize()) == -1)
        max = 256;

    for (fd = 3 /* stderr + 1 */; fd < max; fd++)
        close(fd);
}

static void
spawn_exec(state_t *state)
{
    pid_t sid = 0;
    uid_t uid = 0;
    gid_t gid = 0;

    const watch_t *watch = state->watch;
    const char **args = watch->start;
    const char *executable = *args;
    const char *dir = dir_exists(watch->dir) ? watch->dir : "/";

    /* determine user and group */
    if (watch->uid)
        get_user(watch->uid, &uid, &gid);

    if (watch->gid)
        get_group(watch->gid, &gid);

    /* TODO: configurable mask */
    umask(0);

    /* create session */
    if ((sid = setsid()) == -1)
        log_perror("nyx: setsid");
    else
    {
        log_debug("Created new session group: %d", sid);
    }

    /* set user/group */
    if (gid)
    {
        gid_t groups[] = { gid };

        if (setgroups(1, groups) == -1)
            log_perror("nyx: setgroups");

        if (setgid(gid) == -1)
            log_perror("nyx: setgid");
    }

    if (uid && gid)
    {
        if (initgroups(watch->uid, gid) == -1)
            log_perror("nyx: initgroups");
    }

    if (uid)
    {
        if (setuid(uid) == -1)
            log_perror("nyx: setuid");
    }

    /* set current directory */
    log_debug("Changing current directory to '%s'", dir);

    if (chdir(dir) == -1)
        log_perror("nyx: chdir");

    /* stdin */
    close(STDIN_FILENO);

    if (open("/dev/null", O_RDONLY) == -1)
    {
        fprintf(stderr, "Failed to open /dev/null");
        exit(EXIT_FAILURE);
    };

    /* stdout */
    close(STDOUT_FILENO);

    if (watch->log_file)
    {
        if (open(watch->log_file,
                    O_RDWR | O_APPEND | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP) == -1)
        {
            fprintf(stderr, "Failed to open log file '%s'",
                    watch->log_file);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        if (open("/dev/null", O_WRONLY) == -1)
        {
            fprintf(stderr, "Failed to open /dev/null");
            exit(EXIT_FAILURE);
        }
    }

    /* stderr */
    close(STDERR_FILENO);

    if (watch->error_file)
    {
        if (open(watch->error_file,
                    O_RDWR | O_APPEND | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP) == -1)
        {
            fprintf(stdout, "Failed to open error file '%s'",
                    watch->error_file);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        if (open("/dev/null", O_RDWR) == -1)
        {
            fprintf(stdout, "Failed to open /dev/null");
            exit(EXIT_FAILURE);
        }
    }

    set_environment(watch);
    close_fds();

    /* on success this call won't return */
    execvp(executable, (char * const *)args);

    if (errno == ENOENT)
    {
        fprintf(stderr, "Start command '%s' of watch '%s' is not "
                "executable or does not exist at all",
                executable, watch->name);

        /* TODO: remove watch? */

        exit(EXIT_SUCCESS);
    }

    log_critical_perror("nyx: execvp %s", executable);
}

static pid_t
spawn(state_t *state)
{
    pid_t pid = fork();

    /* fork failed */
    if (pid == -1)
        log_critical_perror("nyx: fork");

    /* child process */
    if (pid == 0)
    {
        /* in 'init mode' we have to fork only once */
        if (state->nyx->is_init)
        {
            /* this call won't return */
            spawn_exec(state);
        }
        /* otherwise we want to 'double fork' */
        else
        {
            pid_t inner_pid = fork();

            if (inner_pid == -1)
                log_critical_perror("nyx: fork");

            if (inner_pid == 0)
            {
                /* this call won't return */
                spawn_exec(state);
            }

            write_pid(inner_pid, state->watch->name, state->nyx);
            exit(EXIT_SUCCESS);
        }
    }

    /* this pid might be the wrong one
     * in case of a 'double-fork' */
    return pid;
}

static void
start_state(state_t *state)
{
    /* start program */
    pid_t pid = spawn(state);

    /* keep track of child pid (in init-mode) */
    if (state->nyx->is_init)
    {
        state->pid = pid;
        write_pid(pid, state->watch->name, state->nyx);
    }
    else
    {
        /* wait for the intermediate forked process
         * to terminate */
        waitpid(pid, NULL, 0);
    }
}

static int
start(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    start_state(state);

    return 1;
}

static int
stopped(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (from != STATE_STOPPING)
        set_state(state, STATE_STARTING);

    return 1;
}

static int
running(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (state->nyx->proc && state->pid)
        nyx_proc_add(state->nyx->proc, state->pid, state->watch->name);

    return 1;
}

#undef DEBUG_LOG_STATE_FUNC

static transition_func_t transition_table[STATE_SIZE][STATE_SIZE] =
{
    /* INIT, UNMONITORED,   STARTING, RUNNING, STOPPING, STOPPED, QUIT */

    /* INIT to ... */
    { NULL, to_unmonitored },

    /* UNMONITORED to ... */
    { NULL, NULL,           start,    running, stop,     stopped, },
    /* STARTING to ... */
    { NULL, to_unmonitored, NULL,     running, stop,     stopped, },
    /* RUNNING to ... */
    { NULL, to_unmonitored, NULL,     NULL,    stop,     stopped, },
    /* STOPPING to ... */
    { NULL, to_unmonitored, NULL,     NULL,    NULL,     stopped, },
    /* STOPPED to ... */
    { NULL, to_unmonitored, start,    NULL,    NULL,     NULL, },

    /* QUIT to ... */
    { NULL }
};

state_t*
find_state_by_name(list_t *states, const char *name)
{
    const char *wname = NULL;
    size_t len = strlen(name);

    list_node_t *node = states->head;

    while (node)
    {
        state_t *state = node->data;
        wname = state->watch->name;

        if (state != NULL && strncmp(wname, name, len) == 0)
            return state;

        node = node->next;
    }

    return NULL;

}

state_t*
find_state_by_pid(list_t *states, pid_t pid)
{
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

int
dispatch_event(int pid, process_event_data_t *event_data, nyx_t *nyx)
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
                if (state->state != STATE_STOPPED)
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

    return 1;
}

int
dispatch_poll_result(int pid, int running, nyx_t *nyx)
{
    log_debug("Incoming polling data for PID %d: running: %s",
            pid, (running ? "true" : "false"));

    state_t *state = find_state_by_pid(nyx->states, pid);

    if (state != NULL)
    {
        state_e next_state = running ? STATE_RUNNING : STATE_STOPPED;

        if (!running)
        {
            state->pid = 0;
            clear_pid(state->watch->name, nyx);

            if (nyx->proc)
                nyx_proc_remove(nyx->proc, pid);
        }

        if (next_state != state->state)
            set_state(state, next_state);
    }

    return 1;
}

state_t *
state_new(watch_t *watch, nyx_t *nyx)
{
    int init = 0;

    sem_t *semaphore = xcalloc(1, sizeof(sem_t));
    state_t *state = xcalloc(1, sizeof(state_t));

    state->nyx = nyx;
    state->watch = watch;
    state->state = STATE_UNMONITORED;

    /* initialize unnamed semaphore
     * - process-local semaphore
     * - initially unlocked (= 1) */
    init = sem_init(semaphore, 0, 1);

    if (init == -1)
        log_critical_perror("nyx: sem_init");

    state->sem = semaphore;

    return state;
}

void
state_destroy(state_t *state)
{
    sem_t *sem = state->sem;

    if (sem != NULL)
    {
        /* first we should unlock the semaphore
         * in case any process is still waiting on it */
        set_state(state, STATE_QUIT);
    }

    if (state->thread != NULL)
    {
        int join = 0;
        void *retval;

        log_debug("Waiting for state thread of watch '%s' to terminate",
                state->watch->name);

        /* join thread */
        join = pthread_join(*state->thread, &retval);

        if (join != 0)
        {
            log_error("Joining of state thread of watch '%s' failed: %d",
                    state->watch->name, join);
        }

        free(state->thread);
    }

    if (sem != NULL)
    {
        sem_destroy(sem);
        free(sem);
    }

    free(state);
    state = NULL;
}

static int
process_state(state_t *state, state_e old_state, state_e new_state)
{
    log_debug("Watch '%s' (PID %d): %s -> %s",
            state->watch->name,
            state->pid,
            state_to_string(old_state),
            state_to_string(new_state));

    int result = 0;
    transition_func_t func = transition_table[old_state][new_state];

    /* no handler for the given state transition
     * meaning the transition is not allowed */
    if (func == NULL)
    {
        log_debug("Transition from %s to %s is not valid",
                state_to_string(old_state),
                state_to_string(new_state));

        return 0;
    }

    result = func(state, old_state, new_state);

    return result;
}

void
state_loop(state_t *state)
{
    int sem_fail = 0, result = 0;

    watch_t *watch = state->watch;
    state_e last_state = STATE_INIT;

    log_debug("Starting state loop for watch '%s'", watch->name);

    /* wait until the event manager triggers this
     * state semaphore */
    while ((sem_fail = sem_wait(state->sem)) == 0)
    {
        state_e current_state = state->state;
        result = 0;

        /* QUIT is handled immediately */
        if (current_state == STATE_QUIT)
        {
            log_info("Watch '%s' terminating", watch->name);
            break;
        }

        /* in case the state did not change
         * we don't have to do anything */
        if (last_state != current_state)
        {
            result = process_state(state, last_state, current_state);

            if (!result)
            {
                /* the state transition failed
                 * so we have to restore the old state */
                state->state = last_state;

                log_warn("Processing state of watch '%s' failed (PID %d)",
                        state->watch->name, state->pid);
            }
        }
        else
        {
            log_debug("Watch '%s' (PID %d): state stayed %s",
                    watch->name, state->pid, state_to_string(last_state));
        }

        last_state = current_state;
        log_debug("Waiting on next state update for watch '%s'", watch->name);
    }

    if (sem_fail)
        log_perror("nyx: sem_wait");
}

void *
state_loop_start(void *state)
{
    state_loop((state_t *)state);

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
