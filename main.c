#include "config.h"
#include "event.h"
#include "log.h"

#include <stdio.h>

static int
handle_process_event(int pid, process_event_data_t *event)
{
    log_debug("Got process event of type: %d (pid %d)", event->type, pid);
    return 0;
}

int
main(int argc, char **argv)
{
    nyx_t *nyx = NULL;

    if (argc < 2)
    {
        fputs("Usage: nyx -qC [FILE]\n", stderr);
        return 1;
    }

    log_debug("Starting nyx");

    nyx = nyx_initialize(argc, argv);


    if (!parse_config(nyx))
        return 1;

    event_loop(&handle_process_event);

    return 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
