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
    "STATE_RESTARTING",
    "STATE_QUIT",
    "STATE_SIZE"
};

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
spawn_exec(state_t *state, int start)
{
    pid_t sid = 0;
    uid_t uid = 0;
    gid_t gid = 0;

    const watch_t *watch = state->watch;
    const char **args = start ? watch->start : watch->stop;
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

    if (start && watch->log_file)
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

    if (start && watch->error_file)
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
        fprintf(stderr, "%s command '%s' of watch '%s' is not "
                "executable or does not exist at all",
                (start ? "Start" : "Stop"),
                executable,
                watch->name);

        /* TODO: remove watch? */

        exit(EXIT_SUCCESS);
    }

    log_critical_perror("nyx: execvp %s", executable);
}

static int
write_pipe(int fd, int value)
{
    FILE *stream = fdopen(fd, "w");

    if (stream != NULL)
    {
        fprintf(stream, "%d\n", value);

        fclose(stream);
        return 1;
    }

    return 0;
}

static int
read_pipe(int fd)
{
    int value = 0;
    FILE *stream = fdopen(fd, "r");

    if (stream != NULL)
    {
        if (fscanf(stream, "%d", &value) != 1)
            value = 0;

        fclose(stream);
    }

    return value;
}

static pid_t
spawn_stop(state_t *state)
{
    pid_t pid = fork();

    if (pid == -1)
        log_critical_perror("nyx: fork");

    if (pid == 0)
    {
        spawn_exec(state, 0);
    }

    return pid;
}

static pid_t
spawn_start(state_t *state)
{
    int pipes[2] = {0};
    int double_fork = !state->nyx->is_init;

    /* in case of a 'double-fork' we need some way to retrieve the
     * resulting process' pid */
    if (double_fork)
    {
        if (pipe(pipes) == -1)
            log_critical_perror("nyx: pipe");
    }

    pid_t pid = fork();
    pid_t outer_pid = pid;

    /* fork failed */
    if (pid == -1)
        log_critical_perror("nyx: fork");

    /* child process */
    if (pid == 0)
    {
        /* in 'init mode' we have to fork only once */
        if (!double_fork)
        {
            /* this call won't return */
            spawn_exec(state, 1);
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
                spawn_exec(state, 1);
            }

            /* close the read end before */
            close(pipes[0]);

            /* now we write the child pid into the pipe */
            if (!write_pipe(pipes[1], inner_pid))
            {
                log_warn("Failed to write double-forked PID %d into pipe", inner_pid);
            }

            exit(EXIT_SUCCESS);
        }
    }

    /* in case of a 'double-fork' we have to read the actual
     * process' pid from the read end of the pipe */
    if (double_fork)
    {
        /* close the write end before */
        close(pipes[1]);

        pid = read_pipe(pipes[0]);

        /* wait for the intermediate forked process
         * to terminate */
        waitpid(outer_pid, NULL, 0);
    }

    return pid;
}

static int
stop(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    nyx_t *nyx = state->nyx;
    watch_t *watch = state->watch;
    pid_t pid = state->pid;
    pid_t stop_pid = 0;

    unsigned times = nyx->options.def_stop_timeout;

    if (watch->stop_timeout)
        times = watch->stop_timeout;

    /* nothing to do */
    if (state->state == STATE_STOPPED)
        return 1;

    /* nothing to stop */
    if (pid < 1)
        return 1;

    /* in case a custom stop command is specified we use that one */
    if (watch->stop)
    {
        stop_pid = spawn_stop(state);
    }
    /* otherwise we try SIGTERM */
    else
    {
        if (kill(pid, SIGTERM) == -1)
        {
            /* process does not exist
             * -> already terminated */
            if (errno == ESRCH)
                return 1;

            log_perror("nyx: kill");
            return 0;
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
    if (stop_pid)
        waitpid(stop_pid, NULL, WNOHANG);

    return 1;
}


static pid_t
start_state(state_t *state)
{
    /* start program */
    pid_t pid = spawn_start(state);

    if (pid)
    {
        state->pid = pid;
        write_pid(pid, state->watch->name, state->nyx);

        log_debug("Retrieved PID %d for watch '%s'", pid, state->watch->name);
    }

    return pid;
}

static int
start(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (start_state(state) > 0)
        set_state(state, STATE_RUNNING);

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
        nyx_proc_add(state->nyx->proc, state->pid, state->watch);

    return 1;
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
    { NULL, to_unmonitored, NULL,     NULL,    stop,     stopped, stop },
    /* STOPPING to ... */
    { NULL, to_unmonitored, NULL,     NULL,    NULL,     stopped, NULL },
    /* STOPPED to ... */
    { NULL, to_unmonitored, start,    running, NULL,     NULL,    start },
    /* RESTARTING to ... */
    { NULL, to_unmonitored, NULL,     running, NULL,     start,   NULL },

    /* QUIT to ... */
    { NULL }
};

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

    sem_t *semaphore = xcalloc1(sizeof(sem_t));
    state_t *state = xcalloc1(sizeof(state_t));

    state->nyx = nyx;
    state->watch = watch;
    state->state = STATE_UNMONITORED;
    state->history = timestack_new(20);

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

    if (state->history)
    {
        timestack_destroy(state->history);
        state->history = NULL;
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

static int
is_flapping(state_t *state, unsigned int changes, int within)
{
    unsigned int i = 0, stopped = 0, started = 0;
    timestack_t *hist = state->history;
    timestack_elem_t *elem = hist->elements;

    if (hist->count < (changes * 2))
        return 0;

    time_t start = time(NULL);

    while (i++ < hist->count)
    {
        state_e value = elem->value;

        if (value != STATE_STARTING && value != STATE_STOPPED)
        {
            elem++;
            continue;
        }

        time_t diff = start - elem->time;

        if (diff > within)
            return 0;

        if (value == STATE_STARTING)
            started++;
        else if (value == STATE_STOPPED)
            stopped++;

        if (started > changes && stopped > changes)
            return 1;

        elem++;
    }

    return 0;
}

static void
safe_sleep(state_t *state, unsigned int seconds)
{
    while (seconds-- > 0 && state->state != STATE_QUIT)
        sleep(1);
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
            timestack_add(state->history, current_state);

            result = process_state(state, last_state, current_state);

            if (!result)
            {
                /* the state transition failed
                 * so we have to restore the old state */
                state->state = last_state;

                timestack_add(state->history, last_state);

                log_warn("Processing state of watch '%s' failed (PID %d)",
                        state->watch->name, state->pid);
            }

            /* check for flapping processes
             * meaning 5 start/stop events within 60 seconds */
            if (is_flapping(state, 5, 60))
            {
                log_warn("Watch '%s' appears to be flapping - delay for 5 minutes", watch->name);

                safe_sleep(state, 5 * 60);
            }

#ifndef NDEBUG
            timestack_dump(state->history);
#endif
        }
        else
        {
            log_debug("Watch '%s' (PID %d): state stayed %s",
                    watch->name, state->pid, state_to_string(last_state));
        }

        if (result)
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
