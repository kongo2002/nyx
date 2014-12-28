#ifndef __NYX_STATE_H__
#define __NYX_STATE_H__

#include "log.h"
#include "watch.h"

#include <sys/types.h>
#include <stdlib.h>

typedef enum
{
    STATE_UNMONITORED,
    STATE_STARTING,
    STATE_RUNNING,
    STATE_STOPPING,
    STATE_STOPPED,
    STATE_SIZE
} state_e;

typedef struct
{
    pid_t pid;
    watch_t *watch;
    state_e state;
} state_t;

state_t *
state_new(watch_t *watch);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
