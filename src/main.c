#include "config.h"
#include "event.h"
#include "log.h"
#include "nyx.h"
#include "state.h"
#include "utils.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
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

    /* start the event handler loop */
    event_loop(nyx, dispatch_event);

    nyx_watches_init(nyx);

    /* tear down */
    log_shutdown();

    nyx_destroy(nyx);

    return 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
