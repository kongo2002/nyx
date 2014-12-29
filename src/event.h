#ifndef __NYX_EVENT_H__
#define __NYX_EVENT_H__

#include "nyx.h"

typedef enum process_event_t
{
    EVENT_FORK,
    EVENT_EXIT,
    NUM_EVENTS
} process_event_t;

typedef struct process_event_fork_t
{
    int parent_pid;
    int parent_thread_group_id;
    int child_pid;
    int child_thread_group_id;
} process_event_fork_t;

typedef struct process_event_exit_t
{
    int pid;
    int exit_code;
    int exit_signal;
    int thread_group_id;
} process_event_exit_t;

typedef struct process_event_data_t
{
    process_event_t type;
    union
    {
        process_event_fork_t fork;
        process_event_exit_t exit;
    };
} process_event_data_t;

typedef int (*process_handler_t)(int pid, process_event_data_t *event_data, nyx_t *nyx);

int
event_loop(nyx_t *nyx, process_handler_t handler);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
