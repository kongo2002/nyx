#include "def.h"
#include "log.h"
#include "state.h"

#include <pthread.h>
#include <errno.h>
#include <unistd.h>

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
            log_error("Joining of state thread failed: %d", join);
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
process_state(state_t *state, state_e old_state)
{
    state_e new_state = state->state;

    log_debug("Watch '%s' (PID %d): %s -> %s",
            state->watch->name,
            state->pid,
            state_to_string(old_state),
            state_to_string(new_state));

    switch (new_state)
    {
        default:
            state->pid = run_forked(state);
            break;
    }

    return 1;
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
        result = 0;

        if (state->state == STATE_QUIT)
        {
            log_info("Watch '%s' terminating", watch->name);
            break;
        }

        if (last_state != state->state)
        {
            result = process_state(state, last_state);

            if (!result)
            {
                /* TODO: do something else than logging? */
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
