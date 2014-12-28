#ifndef __NYX_STATE_H__
#define __NYX_STATE_H__

#include "log.h"
#include "watch.h"

#include <semaphore.h>
#include <stdlib.h>
#include <sys/types.h>

typedef enum
{
    STATE_INIT,
    STATE_UNMONITORED,
    STATE_STARTING,
    STATE_RUNNING,
    STATE_STOPPING,
    STATE_STOPPED,
    STATE_SIZE
} state_e;

const char *state_to_str[] =
{
    "STATE_INIT",
    "STATE_UNMONITORED",
    "STATE_STARTING",
    "STATE_RUNNING",
    "STATE_STOPPING",
    "STATE_STOPPED",
    "STATE_SIZE"
};

typedef struct
{
    pid_t pid;
    state_e state;
    sem_t *sem;
    watch_t *watch;
    nyx_t *nyx;
} state_t;

state_t *
state_new(watch_t *watch, nyx_t *nyx);

void
state_loop(state_t *state);

void
state_loop_start(void *state);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
