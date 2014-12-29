#include "def.h"
#include "log.h"
#include "state.h"

#include <pthread.h>
#include <errno.h>
#include <unistd.h>

typedef int (*transition_func_t)(state_t *, state_e, state_e);

static int
to_unmonitored(state_t *state, state_e from, state_e to)
{
    /* determine if the process is already/still running */

    return 1;
}

static int
stop(state_t *state, state_e from, state_e to)
{

    return 1;
}

static int
start(state_t *state, state_e from, state_e to)
{

    return 1;
}

static int
stopped(state_t *state, state_e from, state_e to)
{

    return 1;
}

static int
running(state_t *state, state_e from, state_e to)
{

    return 1;
}

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

static pid_t
run_forked(state_t *state)
{
    pid_t pid = fork();

    /* fork failed */
    if (pid == -1)
        log_critical_perror("nyx: fork");

    /* child process */
    if (pid == 0)
    {
        const char **args = state->watch->start;
        const char *executable = *args;

        /* TODO: setup signals */

        execvp(executable, (char * const *)args);

        if (errno == ENOENT)
            exit(EXIT_SUCCESS);

        log_critical_perror("nyx: execvp %s", executable);
    }

    return pid;
}


int
dispatch_event(int pid, UNUSED process_event_data_t *event_data, UNUSED nyx_t *nyx)
{
    log_debug("Incoming event data for PID %d", pid);
    return 1;
}

state_t *
state_new(watch_t *watch, nyx_t *nyx)
{
    int init = 0;

    sem_t *semaphore = calloc(1, sizeof(sem_t));

    if (semaphore == NULL)
        log_critical_perror("nyx: calloc");

    state_t *state = calloc(1, sizeof(state_t));

    if (state == NULL)
        log_critical_perror("nyx: calloc");

    state->nyx = nyx;
    state->watch = watch;

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
        state->state = STATE_QUIT;
        sem_post(sem);
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

        last_state = state->state;
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
