/* Copyright 2014-2016 Gregor Uhlenheuer
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
#include "fs.h"
#include "log.h"
#include "process.h"
#include "state.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define NYX_STATE_JOIN_TIMEOUT 30

typedef bool (*transition_func_t)(state_t *, state_e, state_e);

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

void
set_state(state_t *state, state_e value)
{
    /* do not override QUIT signal */
    if (state->state == STATE_QUIT)
        return;

    state->state = value;
    sem_post(state->sem);
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
close_fds(pid_t pid)
{
    char path[256] = {0};

    /* first we try to search in /proc/{pid}/fd */
    snprintf(path, LEN(path)-1, "/proc/%d/fd", pid);

    DIR *dir = opendir(path);
    if (dir)
    {
        int32_t dir_fd = dirfd(dir);

        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL)
        {
            int32_t fd = atoi(entry->d_name);

            if (fd >= 3 && fd != dir_fd)
                close(fd);
        }

        closedir(dir);
        return;
    }

    /* otherwise we will close all file descriptors up
     * to the maximum descriptor index */
    int32_t max;
    if ((max = getdtablesize()) == -1)
        max = 256;

    for (int32_t fd = 3 /* stderr + 1 */; fd < max; fd++)
        close(fd);
}

static void
spawn_exec(state_t *state, bool start)
{
    pid_t sid = 0;
    uid_t uid = 0;
    gid_t gid = 0;

    watch_t *watch = state->watch;
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
        {
            log_perror("nyx: setuid");
        }
        /* in case the uid was modified we adjust the $USER and $HOME
         * environment variables appropriately */
        else
        {
            if (!watch->env)
                watch->env = hash_new(free);

            if (!hash_get(watch->env, "USER"))
            {
                hash_add(watch->env, "USER", strdup(watch->uid));
            }

            if (!hash_get(watch->env, "HOME"))
            {
                struct passwd *pw = getpwuid(uid);

                if (pw && pw->pw_dir)
                    hash_add(watch->env, "HOME", strdup(pw->pw_dir));
            }
        }
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
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1)
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
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1)
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
    close_fds(getpid());

    /* on success this call won't return */
    execvp(executable, (char * const *)args);

    if (errno == ENOENT)
    {
        log_message(state->nyx, NYX_LOG_ERROR,
                "%s command '%s' of watch '%s' is not "
                "executable or does not exist at all",
                (start ? "Start" : "Stop"),
                executable,
                watch->name);

        /* TODO: remove watch? */

        exit(EXIT_SUCCESS);
    }

    log_critical_perror("nyx: execvp %s", executable);
}

static bool
write_pipe(int32_t fd, int32_t value)
{
    FILE *stream = fdopen(fd, "w");

    if (stream != NULL)
    {
        fprintf(stream, "%d\n", value);

        fclose(stream);
        return true;
    }

    return false;
}

static int32_t
read_pipe(int32_t fd)
{
    int32_t value = 0;
    FILE *stream = fdopen(fd, "r");

    if (stream != NULL)
    {
        if (fscanf(stream, "%d", &value) != 1)
            value = 0;

        fclose(stream);
    }
    else
        log_warn("Failed to read of pipe (%d)", fd);

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
        spawn_exec(state, false);
    }

    return pid;
}

static pid_t
spawn_start(state_t *state)
{
    int32_t pipes[2] = {0};
    bool double_fork = !state->nyx->is_init;

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
            spawn_exec(state, true);
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
                spawn_exec(state, true);
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

static bool
stop(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    nyx_t *nyx = state->nyx;
    watch_t *watch = state->watch;
    pid_t pid = state->pid;
    pid_t stop_pid = 0;

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
    if (stop_pid)
        waitpid(stop_pid, NULL, WNOHANG);

    return true;
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

static bool
start(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (start_state(state) > 0)
        set_state(state, STATE_RUNNING);

    return true;
}

static bool
stopped(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (from != STATE_STOPPING && from != STATE_STOPPED)
        set_state(state, STATE_STARTING);

    return true;
}

static bool
running(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

    if (state->nyx->proc && state->pid)
        nyx_proc_add(state->nyx->proc, state->pid, state->watch);

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
    { NULL, to_unmonitored, NULL,     NULL,    stop,     stopped, stop },
    /* STOPPING to ... */
    { NULL, to_unmonitored, NULL,     NULL,    stop,     stopped, NULL },
    /* STOPPED to ... */
    { NULL, to_unmonitored, start,    running, NULL,     stopped, start },
    /* RESTARTING to ... */
    { NULL, to_unmonitored, NULL,     running, NULL,     start,   NULL },

    /* QUIT to ... */
    { NULL }
};

state_t*
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
            state->pid = 0;
            clear_pid(state->watch->name, nyx);

            if (nyx->proc)
                nyx_proc_remove(nyx->proc, pid);
        }

        if (next_state != state->state)
            set_state(state, next_state);
    }

    return true;
}

state_t *
state_new(watch_t *watch, nyx_t *nyx)
{
    sem_t *semaphore = NULL;
    state_t *state = xcalloc1(sizeof(state_t));

    state->nyx = nyx;
    state->watch = watch;
    state->state = STATE_UNMONITORED;
    state->history = timestack_new(MAX(nyx->options.history_size, 20));

#ifndef OSX
    /* initialize unnamed semaphore
     * - process-local semaphore
     * - initially unlocked (= 1) */
    semaphore = xcalloc1(sizeof(sem_t));

    int32_t init = sem_init(semaphore, 0, 1);

    if (init == -1)
        log_critical_perror("nyx: sem_init");
#else
    log_debug("Trying to create a new named semaphore (%s)", watch->name);

    /* initialize a named-semaphore as OSX does not support unnamed ones
     * - chmod of the semaphore (0644)
     * - initially unlocked (= 1) */
    semaphore = sem_open(watch->name, O_CREAT | O_EXCL, 0644, 1);

    if (semaphore == SEM_FAILED)
    {
        log_debug("Semaphore (%s) already exists - trying to unlink",
                watch->name);

        /* the semaphore should not exist beforehand ->
         * try to remove and retry -> then fail */
        int32_t err = sem_unlink(watch->name);
        if (err == 0)
        {
            log_debug("Try to create semaphore (%s) again", watch->name);

            /* remove succeeded -> try again */
            semaphore = sem_open(watch->name, O_CREAT | O_EXCL, 0644, 1);
        }
        else
            log_critical_perror("nyx: sem_unlink");
    }

    if (semaphore == SEM_FAILED)
        log_critical_perror("nyx: sem_open");
#endif

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
        int32_t join = 0, join_timeout = MAX(NYX_STATE_JOIN_TIMEOUT, state->watch->stop_timeout);
        time_t now = time(NULL);
        const char *name = state->watch->name;

        const struct timespec timeout =
        {
            .tv_sec = now + join_timeout,
            .tv_nsec = 0
        };

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

    if (sem != NULL)
    {
#ifndef OSX
        sem_destroy(sem);
        free(sem);
#else
        sem_close(sem);
        sem_unlink(state->watch->name);
#endif
    }

    if (state->history)
    {
        timestack_destroy(state->history);
        state->history = NULL;
    }

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

        return 0;
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

    time_t start_time = time(NULL);

    while (i++ < hist->count)
    {
        state_e value = elem->value;

        if (value != STATE_STARTING && value != STATE_STOPPED)
        {
            elem++;
            continue;
        }

        time_t diff = start_time - elem->time;

        if (diff > within)
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

static void
safe_sleep(state_t *state, uint32_t seconds)
{
    while (seconds-- > 0 && state->state != STATE_QUIT)
        sleep(1);
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
    while ((sem_fail = sem_wait(state->sem)) == 0)
    {
        state_e current_state = state->state;

        /* QUIT is handled immediately */
        if (current_state == STATE_QUIT)
        {
            log_info("Watch '%s' terminating", watch->name);
            break;
        }

        if (last_state != current_state)
        {
            timestack_add(state->history, current_state);

#ifndef NDEBUG
            timestack_dump(state->history);
#endif
        }

        bool result = process_state(state, last_state, current_state);

        if (!result)
        {
            /* the state transition failed
             * so we have to restore the old state */
            state->state = last_state;

            timestack_add(state->history, last_state);
        }

        /* check for flapping processes
         * meaning 5 start/stop events within 60 seconds
         * TODO: configurable */
        if (is_flapping(state, 5, 60))
        {
            log_warn("Watch '%s' appears to be flapping - delay for 5 minutes. "
                     "Probably the start command is not executable or does "
                     "not exist at all.",
                     watch->name);

            /* TODO: use select instead */
            safe_sleep(state, 5 * 60);
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
