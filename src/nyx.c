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
#include "def.h"
#include "fs.h"
#include "hash.h"
#include "log.h"
#include "nyx.h"
#include "state.h"
#include "watch.h"

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

static void
_watch_destroy(void *watch)
{
    watch_destroy((watch_t *)watch);
}

static void
_state_destroy(void *state)
{
    state_destroy((state_t *)state);
}

void
print_usage(FILE *out)
{
    fputs("usage: nyx [options] <file>\n", out);
}

void
print_help(void)
{
    print_usage(stdout);
    puts("\n"
         "Options:\n"
         "   -c  --config    (path to configuration file)\n"
         "   -D  --no-daemon (do not daemonize)\n"
         "   -s  --syslog    (log into syslog)\n"
         "   -q  --quiet     (output error messages only)\n"
         "   -C  --no-color  (no terminal coloring)\n"
         "   -V  --version   (version information)\n"
         "   -h  --help      (print this help)");
    exit(EXIT_SUCCESS);
}

static const struct option long_options[] =
{
    { .name = "help",      .has_arg = 0, .flag = NULL, .val = 'h'},
    { .name = "config",    .has_arg = 0, .flag = NULL, .val = 'c'},
    { .name = "no-color",  .has_arg = 0, .flag = NULL, .val = 'C'},
    { .name = "no-daemon", .has_arg = 0, .flag = NULL, .val = 'D'},
    { .name = "quiet",     .has_arg = 0, .flag = NULL, .val = 'q'},
    { .name = "syslog",    .has_arg = 0, .flag = NULL, .val = 's'},
    { .name = "version",   .has_arg = 0, .flag = NULL, .val = 'V'},
    { NULL }
};

static void
handle_child_stop(UNUSED int signum)
{
    pid_t pid;
    int last_errno = errno;

    log_debug("Received child stop signal - waiting for termination");

    /* wait for all child processes */
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        /* do nothing */
    }

    errno = last_errno;
}

void
setup_signals(UNUSED nyx_t *nyx, void (*terminate_handler)(int))
{
    log_debug("Setting up signals");

    struct sigaction action =
    {
        .sa_flags = SA_NOCLDSTOP | SA_RESTART,
        .sa_handler = handle_child_stop
    };

    sigfillset(&action.sa_mask);

    /* register SIGCHLD handler */
    sigaction(SIGCHLD, &action, NULL);

    /* register handler for termination:
     * SIGTERM and SIGINT */
    action.sa_handler = terminate_handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
}

nyx_t *
nyx_initialize(int argc, char **args)
{
    int arg = 0, i = 0, j = 0, err = 0;

    nyx_t *nyx = calloc(1, sizeof(nyx_t));

    if (nyx == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    /* parse command line arguments */
    while ((arg = getopt_long(argc, args, "hqsCDVc:", long_options, NULL)) != -1)
    {
        switch (arg)
        {
            case 'q':
                nyx->options.quiet = 1;
                break;
            case 's':
                nyx->options.syslog = 1;
                break;
            case 'C':
                nyx->options.no_color = 1;
                break;
            case 'D':
                nyx->options.no_daemon = 1;
                break;
            case 'c':
                nyx->options.config_file = optarg;
                break;
            case 'V':
                puts("nyx " NYX_VERSION);
                free(nyx);
                exit(EXIT_SUCCESS);
                break;
            case 'h':
                free(nyx);
                print_help();
                break;
            case '?':
                free(nyx);
                exit(EXIT_FAILURE);
                break;
        }
    }

    /* if a config file is given
     * this has to be a deamon */
    nyx->is_daemon = nyx->options.config_file && *nyx->options.config_file;

    /* process remaining arguments if given */
    if (optind < argc)
    {
        nyx->options.commands = xcalloc(argc-optind+1, sizeof(char *));

        for (j = 0, i = optind; i < argc; i++, j++)
        {
            nyx->options.commands[j] = args[i];
        }
    }

    log_init(nyx);

    /* further initialization is necessary in daemon mode only */
    if (!nyx->is_daemon)
        return nyx;

    /* set default options */
    nyx->options.def_start_timeout = 5;
    nyx->options.def_grace = 5;

    nyx->pid_dir = determine_pid_dir();

    if (nyx->pid_dir == NULL)
        return NULL;

    nyx->pid = getpid();
    nyx->is_init = nyx->pid == 1;
    nyx->watches = hash_new(8, _watch_destroy);
    nyx->states = list_new(_state_destroy);

    /* initialize eventfd with an initial value of '0' */
    nyx->event = eventfd(0, 0);

    if (nyx->event < 1)
    {
        log_perror("nyx: eventfd");
    }

    /* start connector */
    nyx->connector_thread = xcalloc(1, sizeof(pthread_t));

    err = pthread_create(nyx->connector_thread, NULL, connector_start, nyx);

    if (err)
    {
        log_perror("nyx: pthread_create");
        log_error("Failed to initialize connector thread");

        free(nyx->connector_thread);
        nyx->connector_thread = NULL;
    }

    return nyx;
}

int
nyx_watches_init(nyx_t *nyx)
{
    int rc = 1, init = 0;
    const char *key = NULL;
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(nyx->watches);

    while (hash_iter(iter, &key, &data))
    {
        state_t *state = NULL;
        watch_t *watch = data;

        if (!watch_validate(watch))
        {
            log_error("Invalid watch '%s' - skipping", watch->name);
            continue;
        }

        log_debug("Initialize watch '%s'", watch->name);

        /* create new state instance */
        state = state_new(watch, nyx);
        list_add(nyx->states, state);

        /* start a new thread for each state */
        state->thread = xcalloc(1, sizeof(pthread_t));

        /* create with default thread attributes */
        rc = pthread_create(state->thread, NULL, state_loop_start, state);
        if (rc != 0)
            log_critical_perror("Failed to create thread, error: %d", rc);

        init++;
    }

    free(iter);
    return init > 0;
}

void
nyx_destroy(nyx_t *nyx)
{
    int signal_error = 0;

    log_debug("Tearing down nyx");

    if (nyx == NULL)
        return;

    /* signal termination via eventfd (if existing) */
    if (nyx->event)
    {
        uint64_t signal = 4;
        signal_error = write(nyx->event, &signal, sizeof(signal));

        if (signal_error == -1)
        {
            log_perror("nyx: write");
        }
    }

    /* tear down connector first */
    if (nyx->connector_thread)
    {
        pthread_t connector = *nyx->connector_thread;

        /* signal for termination failed
         * -> we have to force exit */
        if (signal_error == -1)
            pthread_cancel(connector);

        pthread_join(connector, NULL);

        free(nyx->connector_thread);
        nyx->connector_thread = NULL;
    }

    if (nyx->states)
    {
        list_destroy(nyx->states);
        nyx->states = NULL;
    }

    if (nyx->watches)
    {
        hash_destroy(nyx->watches);
        nyx->watches = NULL;
    }

    if (nyx->options.commands)
    {
        free(nyx->options.commands);
        nyx->options.commands = NULL;
    }

    free(nyx);
    nyx = NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
