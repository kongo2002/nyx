/* Copyright 2014-2015 Gregor Uhlenheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

static int
command_mode(nyx_t *nyx)
{
    int success = 0;
    command_t *command = NULL;

    if (!nyx->options.commands)
    {
        log_error("no command specified at all");
        return 0;
    }

    if ((command = parse_command(nyx->options.commands)) != NULL)
    {
        printf("<<< %s\n", command->name);
        success = connector_call(nyx->options.commands);
    }
    else
    {
        log_error("Invalid command '%s'", nyx->options.commands[0]);
        return 0;
    }

    return success;
}

int
main(int argc, char **argv)
{
    int success = 0;
    nyx_t *nyx = NULL;

    if (argc < 2)
    {
        print_usage(stderr);
        fputs("\nTry 'nyx -h' for more information\n", stderr);
        return 1;
    }

    /* initialize log and main application data */
    nyx = nyx_initialize(argc, argv);

    if (nyx != NULL)
    {
        success = nyx->is_daemon
            ? daemon_mode(nyx)
            : command_mode(nyx);
    }

    nyx_destroy(nyx);
    log_shutdown();

    return !success;
}

/* vim: set et sw=4 sts=4 tw=80: */
