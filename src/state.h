#ifndef __NYX_STATE_H__
#define __NYX_STATE_H__

#include "event.h"
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
    STATE_QUIT,
    STATE_SIZE
} state_e;

typedef struct
{
    pid_t pid;
    state_e state;
    sem_t *sem;
    pthread_t *thread;
    watch_t *watch;
    nyx_t *nyx;
} state_t;

inline const char *
state_to_string(state_e state);

state_t *
state_new(watch_t *watch, nyx_t *nyx);

void
state_destroy(state_t *state);

void
state_loop(state_t *state);

void *
state_loop_start(void *state);

int
dispatch_event(int pid, process_event_data_t *event_data, nyx_t *nyx);

int
dispatch_poll_result(int pid, int running, nyx_t *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
