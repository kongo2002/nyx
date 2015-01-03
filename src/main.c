#include "config.h"
#include "connector.h"
#include "event.h"
#include "log.h"
#include "nyx.h"
#include "poll.h"
#include "state.h"
#include "utils.h"

#include <stdio.h>

static int
daemon_mode(nyx_t *nyx)
{
    /* parse config */
    if (!parse_config(nyx))
    {
        if (hash_count(nyx->watches) < 1)
            log_error("No watches configured - terminating now");

        return 0;
    }

    if (!nyx_watches_init(nyx))
    {
        log_error("No valid watched configured - terminating now");

        return 0;
    }

    /* start the event handler loop */
    if (!event_loop(nyx, dispatch_event))
    {
        log_warn("Failed to initialize event manager "
                  "- trying polling mechanism next");

        if (!poll_loop(nyx, dispatch_poll_result))
        {
            log_error("Failed to start loop manager as well - terminating");
            return 0;
        }
    }

    return 1;
}

int
main(int argc, char **argv)
{
    int failed = 0;
    nyx_t *nyx = NULL;

    if (argc < 2)
    {
        print_usage(stderr);
        fputs("\nTry 'nyx -h' for more information\n", stderr);
        return 1;
    }

    /* initialize log and main application data */
    nyx = nyx_initialize(argc, argv);

    if (nyx == NULL)
    {
        failed = 1;
        goto teardown;
    }

    if (is_daemon(nyx))
        failed = !daemon_mode(nyx);
    else
    {
        const char *result = NULL;
        connector_command_e command;

        if (parse_command(argv[1], &command))
            result = connector_call(command);

        if (result != NULL)
        {
            printf("%s\n", result);

            free((void *)result);
            result = NULL;
        }
    }

teardown:
    nyx_destroy(nyx);
    log_shutdown();

    return failed;
}

/* vim: set et sw=4 sts=4 tw=80: */
