#include "config.h"
#include "event.h"

#include <stdio.h>

static int
handle_process_event(int pid, process_event_data_t *event)
{
    printf("Got process event of type: %d (pid %d)\n", event->type, pid);
    return 0;
}

int
main(int argc, char **argv)
{
    puts("Starting nyx");

    if (argc < 2)
    {
        fputs("No config file given\n", stderr);
        return 1;
    }

    if (!parse_config(argv[1]))
        return 1;

    event_loop(&handle_process_event);

    return 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
