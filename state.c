#include "log.h"
#include "state.h"

int
dispatch_event(int pid, process_event_data_t *event_data, nyx_t *nyx)
{
    log_debug("Incoming event data for PID %d", pid);
    return 1;
}

state_t *
state_new(watch_t *watch, nyx_t *nyx)
{
    int init = 0;
    sem_t *semaphore = NULL;
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
            /* TODO */
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

    /* wait until the event manager triggers this
     * state semaphore */
    while ((sem_fail = sem_wait(state->sem)) == 0)
    {
        result = 0;

        if (last_state != state->state)
        {
            result = process_state(state, last_state);
        }
        else
        {
            log_debug("Watch '%s' (PID %d): state stayed %s",
                    watch->name, state->pid, state_to_string(last_state));
        }

        if (!result)
        {
            /* TODO: do something else than logging? */
            log_warn("Processing state of watch '%s' failed (PID %d)",
                    state->watch->name, state->pid);
        }

        last_state = state->state;
    }

    if (sem_fail)
        log_perror("nyx: sem_wait");
}

void
state_loop_start(void *state)
{
    state_loop((state_t *)state);
}

/* vim: set et sw=4 sts=4 tw=80: */
