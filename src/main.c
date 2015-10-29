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

#include "connector.h"
#include "command.h"
#include "event.h"
#include "log.h"
#include "nyx.h"
#include "poll.h"
#include "state.h"
#include "utils.h"

#include <stdio.h>

static nyx_error_e
daemon_mode(nyx_t *nyx)
{
    if (!nyx_watches_init(nyx))
    {
        log_error("No valid watched configured - terminating now");

        return NYX_NO_VALID_WATCH;
    }

    /* start the event handler loop (not supported on OSX)*/
#ifndef OSX
    if (!event_loop(nyx, dispatch_event))
    {
        log_warn("Failed to initialize event manager "
                  "- trying polling mechanism next");

        log_warn("Try enabling CONFIG_CONNECTOR in your kernel config "
                 "and run nyx with root privileges");
#endif

        if (!poll_loop(nyx, dispatch_poll_result))
        {
            log_error("Failed to start loop manager as well - terminating");
            return NYX_FAILURE;
        }
#ifndef OSX
    }
#endif

    return NYX_SUCCESS;
}

static nyx_error_e
command_mode(nyx_t *nyx)
{
    nyx_error_e retcode = NYX_FAILURE;

    if (!nyx->options.commands)
    {
        log_error("no command specified at all");
        return NYX_NO_COMMAND;
    }

    if (parse_command(nyx->options.commands) != NULL)
    {
        retcode = connector_call(nyx->options.commands,
                nyx->options.quiet);
    }
    else
    {
        log_error("Invalid command '%s'", nyx->options.commands[0]);
        return NYX_INVALID_COMMAND;
    }

    return retcode;
}

int
main(int argc, char **argv)
{
    nyx_error_e retcode = NYX_FAILURE;
    nyx_t *nyx = NULL;

    if (argc < 2)
    {
        print_usage(stderr);
        fputs("\nTry 'nyx -h' for more information\n", stderr);
        return NYX_INVALID_USAGE;
    }

    /* initialize log and main application data */
    nyx = nyx_initialize(argc, argv, &retcode);

    if (nyx != NULL)
    {
        retcode = nyx->is_daemon
            ? daemon_mode(nyx)
            : command_mode(nyx);
    }

    nyx_destroy(nyx);
    log_shutdown();

    return retcode;
}

/* vim: set et sw=4 sts=4 tw=80: */
