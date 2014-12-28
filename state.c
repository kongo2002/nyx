#include "state.h"

state_t *
state_new(watch_t *watch)
{
    state_t *state = calloc(1, sizeof(state_t));

    if (state == NULL)
        log_critical_perror("nyx: calloc");

    state->watch = watch;

    return state;
}

/* vim: set et sw=4 sts=4 tw=80: */
