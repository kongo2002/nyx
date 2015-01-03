#include "def.h"
#include "fs.h"
#include "log.h"
#include "process.h"
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static void
set_state(state_t *state, state_e value)
{
    state->state = value;
    sem_post(state->sem);
}

#define DEBUG_LOG_STATE_FUNC \
    log_debug("State transition function of watch '%s' " \
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
        pid_t sid = 0;
        uid_t uid = 0;
        gid_t gid = 0;
        mode_t old_mode;

        const watch_t *watch = state->watch;
        const char **args = state->watch->start;
        const char *executable = *args;
        const char *dir = dir_exists(watch->dir) ? watch->dir : "/";

        /* determine user and group */
        if (watch->uid)
            get_user(watch->uid, &uid, &gid);

        if (watch->gid)
            get_group(watch->gid, &gid);

        /* TODO */
        old_mode = umask(0);

        log_debug("Reset umask - old mask: %04o", old_mode);

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
        if (chdir(dir) == -1)
            log_perror("nyx: chdir");

        /* close open file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        /* TODO: redirect somewhere? */

        if (open("/dev/null", O_RDONLY) == -1)
            log_perror("nyx: open");

        if (open("/dev/null", O_WRONLY) == -1)
            log_perror("nyx: open");

        if (open("/dev/null", O_RDWR) == -1)
            log_perror("nyx: open");

        set_environment(watch);

        execvp(executable, (char * const *)args);

        if (errno == ENOENT)
        {
            /* program does not exist or is not executable */

            /* TODO: remove watch? */

            exit(EXIT_SUCCESS);
        }

        log_critical_perror("nyx: execvp %s", executable);
    }

    return pid;
}

static void
start_state(state_t *state)
{
    /* start program */
    pid_t pid = spawn(state);

    /* keep track of child pid */
    if (pid > 0)
    {
        state->pid = pid;
        write_pid(pid, state->watch->name, state->nyx);
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

    set_state(state, STATE_STARTING);

    return 1;
}

static int
running(state_t *state, state_e from, state_e to)
{
    DEBUG_LOG_STATE_FUNC;

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

static state_t*
find_state(list_t *states, pid_t pid)
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
            state = find_state(nyx->states, pid);

            if (state != NULL)
            {
                if (state->state != STATE_STOPPED)
                    set_state(state, STATE_STOPPED);
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

    state_t *state = find_state(nyx->states, pid);

    if (state != NULL)
    {
        state_e next_state = running ? STATE_RUNNING : STATE_STOPPED;

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
