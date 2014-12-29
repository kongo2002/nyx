#include "config.h"
#include "event.h"
#include "log.h"
#include "nyx.h"
#include "poll.h"
#include "state.h"
#include "utils.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
    int exit = 0;
    nyx_t *nyx = NULL;

    if (argc < 2)
    {
        print_usage(stderr);
        fputs("\nTry 'nyx -h' for more information\n", stderr);
        return 1;
    }

    /* initialize log and main application data */
    nyx = nyx_initialize(argc, argv);

    /* parse config */
    if (!parse_config(nyx))
        return 1;

    nyx_watches_init(nyx);

    /* start the event handler loop */
    if (!event_loop(nyx, dispatch_event))
    {
        log_error("Failed to initialize event manager "
                  "- trying polling mechanism next");

        if (!poll_loop(nyx, dispatch_poll_result))
        {
            log_error("Failed to start loop manager as well - terminating");
            exit = 1;
        }
    }

    /* tear down */
    nyx_destroy(nyx);
    log_shutdown();

    return exit;
}

/* vim: set et sw=4 sts=4 tw=80: */
