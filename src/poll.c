#include "def.h"
#include "log.h"
#include "poll.h"
#include "process.h"
#include "state.h"

#include <signal.h>
#include <unistd.h>

static const unsigned int POLLING_INTERVAL = 5;

static volatile int need_exit = 0;

static void
on_sigint(UNUSED int unused)
{
    log_debug("SIGINT - exiting polling manager loop");
    need_exit = 1;
}

static int
check_process_running(pid_t pid)
{
    if (kill(pid, 0) == 0)
    {
        /* process is either running or a zombie */
        return 1;
    }

    /* TODO: handle different errors? */

    return 0;
}

int
poll_loop(nyx_t *nyx, poll_handler_t handler)
{
    list_t *states = nyx->states;

    /* TODO: does this belong in here? */
    signal(SIGINT, &on_sigint);
    siginterrupt(SIGINT, 1);

    log_debug("Starting polling manager loop");

    while (!need_exit)
    {
        list_node_t *node = states->head;

        while (node)
        {
            int running = 0;
            state_t *state = node->data;
            pid_t pid = state->pid;

            if (pid < 1)
                pid = determine_pid(state->watch->name, nyx);

            if (pid > 0)
            {
                running = check_process_running(pid);

                log_debug("Poll: watch '%s' process with PID %d is %srunning",
                        state->watch->name, pid,
                        (running ? "" : "not "));

                handler(pid, running, nyx);
            }
            else
            {
                /* TODO: try to determine pid */
                log_debug("Poll: watch '%s' has no PID (yet)",
                        state->watch->name);
            }

            node = node->next;
        }

        /* in case we were interrupted by a signal
         * we don't want to be stuck in here sleeping */
        if (!need_exit)
            sleep(POLLING_INTERVAL);
    }

    return 1;
}

/* vim: set et sw=4 sts=4 tw=80: */
