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
    const char *config;
    nyx_t *nyx = NULL;

    log_info("Starting nyx");

    if (argc < 2)
    {
        log_warn("No config file given");
        return 1;
    }

    config = argv[1];
    nyx = nyx_initialize(config);

    if (!parse_config(nyx))
        return 1;

    event_loop(&handle_process_event);

    return 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
