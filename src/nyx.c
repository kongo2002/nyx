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
#include "command.h"
#include "def.h"
#include "fs.h"
#include "log.h"
#include "nyx.h"
#include "process.h"
#include "state.h"
#include "watch.h"

#ifdef USE_PLUGINS
#include "plugins.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/**
 * @brief Watch destroy callback function
 * @param watch watch to destroy
 */
static void
_watch_destroy(void *watch)
{
    watch_destroy((watch_t *)watch);
}

/**
 * @brief State destroy callback function
 * @param state state to destroy
 */
static void
_state_destroy(void *state)
{
    state_destroy((state_t *)state);
}

/**
 * @brief Print the usage information
 * @param out stream to write the usage information into
 */
void
print_usage(FILE *out)
{
    fputs("Usage: nyx -c <file> [options]\n"
          "       nyx <command>\n"
          "\n"
          "Available commands:\n", out);

    print_commands(out);
}

/**
 * @brief Print help information to STDOUT
 */
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
         "   -h  --help      (print this help)\n"
         "\n"
         "Configuration:\n"
#ifdef USE_PLUGINS
         "   plugin support: yes\n"
#else
         "   plugin support: no\n"
#endif
#ifdef USE_SSL
         "   SSL support:    yes"
#else
         "   SSL support:    no"
#endif
         );
    exit(EXIT_SUCCESS);
}

static const struct option long_options[] =
{
    { .name = "help",      .has_arg = 0, .flag = NULL, .val = 'h'},
    { .name = "config",    .has_arg = 1, .flag = NULL, .val = 'c'},
    { .name = "no-color",  .has_arg = 0, .flag = NULL, .val = 'C'},
    { .name = "no-daemon", .has_arg = 0, .flag = NULL, .val = 'D'},
    { .name = "quiet",     .has_arg = 0, .flag = NULL, .val = 'q'},
    { .name = "syslog",    .has_arg = 0, .flag = NULL, .val = 's'},
    { .name = "version",   .has_arg = 0, .flag = NULL, .val = 'V'},
    { NULL, 0, NULL, 0 }
};

/**
 * @brief Callback to recieve child termination signals
 * @param signum signal number
 */
static void
handle_child_stop(UNUSED int signum)
{
    int last_errno = errno;

    log_debug("Received child stop signal - waiting for termination");

    /* wait for all child processes */
    while (waitpid(-1, NULL, WNOHANG) > 0)
    {
        /* do nothing */
    }

    errno = last_errno;
}

static void
handle_sigpipe(UNUSED int signal)
{
    log_debug("Received SIGPIPE - ignoring for now");
}

/**
 * @brief Setup the main program signal handlers
 * @param nyx               nyx instance
 * @param terminate_handler program termination handler callback
 */
void
setup_signals(UNUSED nyx_t *nyx, void (*terminate_handler)(int))
{
    log_debug("Setting up signals");

    struct sigaction action =
    {
        .sa_flags = SA_NOCLDSTOP | SA_RESTART,
        .sa_handler = terminate_handler
    };

    sigfillset(&action.sa_mask);

    /* register handler for termination:
     * SIGTERM and SIGINT */
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    /* register SIGPIPE handler */
    action.sa_handler = handle_sigpipe;
    sigaction(SIGPIPE, &action, NULL);

    /* register SIGCHLD handler */
    if (nyx->is_init)
    {
        action.sa_handler = handle_child_stop;
        sigaction(SIGCHLD, &action, NULL);
    }

    nyx->terminate_handler = terminate_handler;
}

/**
 * @brief Determine whether a nyx instance is currently running
 * @param nyx nyx instance
 * @return pid of the running nyx instance or 0
 */
static pid_t
is_nyx_running(nyx_t *nyx)
{
    pid_t nyx_pid = determine_pid("nyx", nyx);

    /* there is no nyx pid at all */
    if (nyx_pid < 1)
        return 0;

    if (check_process_running(nyx_pid))
        return nyx_pid;

    return 0;
}

/**
 * @brief Daemonize the running nyx instance
 * @param nyx nyx instance
 * @return 1 on success, 0 otherwise
 */
static int
daemonize(nyx_t *nyx)
{
    pid_t pid = fork();

    if (pid == -1)
    {
        log_perror("nyx: fork");
        return 0;
    }

    /* child process */
    if (pid == 0)
    {
        if (setsid() == -1)
        {
            log_perror("nyx: setsid");
            return 0;
        }

        const char *log_file = nyx->options.log_file
            ? nyx->options.log_file
            : NYX_DEFAULT_LOG_FILE;

        /* reopen file descriptors */

        close(STDIN_FILENO);
        if (open("/dev/null", O_RDONLY) == -1)
            log_critical_perror("nyx: open");

        /* try to use /var/log/nyx.log otherwise /dev/null */
        close(STDOUT_FILENO);
        if (nyx->options.syslog ||
                open(log_file,
                    O_WRONLY | O_APPEND | O_CREAT,
                    S_IRUSR | S_IWUSR |
                    S_IRGRP | S_IWGRP |
                    S_IROTH | S_IWOTH) == -1)
        {
            if (open("/dev/null", O_WRONLY) == -1)
                log_critical_perror("nyx: open");
        }

        close(STDERR_FILENO);
        if (open("/dev/null", O_RDWR) == -1)
            log_critical_perror("nyx: open");

        /* refresh to new daemon pid */
        nyx->pid = getpid();
    }
    else
    {
        if (!write_pid(pid, "nyx", nyx))
            log_warn("Failed to persist PID (%d) of running nyx instance", pid);

        log_info("Daemonized nyx on PID %d", pid);
        exit(EXIT_SUCCESS);
    }

    return 1;
}

/**
 * @brief Daemon mode initialization
 * @param nyx nyx instance
 * @return 1 on success, 0 otherwise
 */
static int
initialize_daemon(nyx_t *nyx)
{
    int err = 0;
    pid_t pid = 0;

    /* set default options */
    nyx->options.def_start_timeout = 5;
    nyx->options.def_stop_timeout = 5;
    nyx->options.polling_interval = 5;
    nyx->options.check_interval = 30;
    nyx->options.history_size = 20;
    nyx->options.http_port = 0;

    nyx->pid_dir = determine_pid_dir();

    if (nyx->pid_dir == NULL)
        return 0;

    nyx->pid = getpid();
    nyx->is_init = nyx->pid == 1;

    /* try to check if a nyx instance is already running */
    if ((pid = is_nyx_running(nyx)) > 0)
    {
        log_error("nyx instance appears to be running on PID %d - PID folder '%s'",
                  pid, nyx->pid_dir);
        return 0;
    }

    nyx->watches = hash_new(_watch_destroy);
    nyx->states = list_new(_state_destroy);
    nyx->state_map = hash_new(NULL);

    /* parse config */
    if (!parse_config(nyx))
        return 0;

    /* nyx should run as a daemon process */
    if (!nyx->is_init && !nyx->options.no_daemon)
    {
        if (!daemonize(nyx))
        {
            log_error("Failed to daemonize nyx");
            return 0;
        }
    }
    /* otherwise in the foreground */
    else
    {
        if (!write_pid(nyx->pid, "nyx", nyx))
        {
            log_warn("Failed to persist PID (%d) of running nyx instance",
                    nyx->pid);
        }
    }

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

#ifdef USE_PLUGINS
    /* load plugins if enabled */
    nyx->plugins = discover_plugins(nyx->options.plugins,
            nyx->options.plugin_config);
#endif

    return 1;
}

/**
 * @brief Main program initialization
 * @param argc number of program arguments
 * @param args command line arguments
 * @return nyx instance
 */
nyx_t *
nyx_initialize(int argc, char **args)
{
    int arg = 0;

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
     * this has to be a daemon */
    nyx->is_daemon = nyx->options.config_file && *nyx->options.config_file;

    /* initialize logging */
    log_init(nyx);

    /* globally ignore SIGUSR1 */
    signal(SIGUSR1, SIG_IGN);

    if (nyx->is_daemon)
    {
        if (!initialize_daemon(nyx))
        {
            nyx_destroy(nyx);
            return NULL;
        }
    }
    else
    {
        /* parse remaining arguments in non-daemon mode only */
        if (optind < argc)
        {
            int i = 0, j = 0;

            nyx->options.commands = xcalloc(argc-optind+1, sizeof(char *));

            for (j = 0, i = optind; i < argc; i++, j++)
            {
                nyx->options.commands[j] = args[i];
            }
        }
    }

    return nyx;
}

/**
 * @brief Callback to any proc system event
 * @param event event type
 * @param proc  proc system instance
 * @param nyx   nyx instance
 * @return 0 if no further events should be handled, 1 otherwise
 */
static int
handle_proc_event(proc_event_e event, proc_stat_t *proc, void *nyx)
{
    hash_t *states = ((nyx_t *)nyx)->state_map;

    log_debug("Got process event %d of process '%s'", event, proc->name);

    state_t *state = hash_get(states, proc->name);

    if (state != NULL)
    {
        /* port and HTTP check should only be taken into account
         * if the state is running at least for some time */
        if (event == PROC_HTTP_CHECK_FAILED || event == PROC_PORT_NOT_OPEN)
        {
            if (state->history == NULL || state->history->count < 1)
                return 1;

            time_t now = time(NULL);
            timestack_elem_t *newest = &state->history->elements[0];
            int last_state_ago = difftime(now, newest->time);

            /* TODO: configurable */
            if (last_state_ago < 30)
            {
                log_debug("Ignoring process event %d of process '%s' "
                    "because the latest state change was just %ds ago",
                    event, proc->name, last_state_ago);

                return 1;
            }
        }

        set_state(state, STATE_RESTARTING);
        return 0;
    }

    return 1;
}

/**
 * @brief Proc system initialization
 * @param nyx nyx instance
 * @return 1 on success, 0 otherwise
 */
static int
nyx_proc_initialize(nyx_t *nyx)
{
    /* try to initialize proc watch/thread */
    nyx->proc = nyx_proc_init(nyx->pid);

    if (nyx->proc != NULL)
    {
        nyx->proc->event_handler = handle_proc_event;

        nyx->proc_thread = xcalloc1(sizeof(pthread_t));

        int err = pthread_create(nyx->proc_thread, NULL, nyx_proc_start, nyx);

        if (err)
        {
            log_perror("nyx: pthread_create");
            log_error("Failed to initialize proc watch - unable to monitor process' statistics");

            free(nyx->proc_thread);
            nyx->proc_thread = NULL;

            free(nyx->proc);
            nyx->proc = NULL;
        }
    }

    return nyx->proc != NULL;
}

static int
proc_required(nyx_t *nyx)
{
    int required = 0;
    const char *key = NULL;
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(nyx->watches);

    while (hash_iter(iter, &key, &data))
    {
        watch_t *watch = data;

        if (watch_validate(watch) &&
            (watch->max_cpu > 0 ||
             watch->max_memory > 0 ||
             watch->port_check > 0 ||
             watch->http_check != NULL))
        {
            required = 1;
            break;
        }
    }

    free(iter);

    return required;
}

/**
 * @brief Initialize watches
 * @param nyx nyx instance
 * @return 1 on success, 0 otherwise
 */
int
nyx_watches_init(nyx_t *nyx)
{
    int rc = 1, init = 0;
    const char *key = NULL;
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(nyx->watches);

    /* initialize proc system if necessary */
    if (proc_required(nyx))
    {
        if (nyx_proc_initialize(nyx))
        {
            log_debug("Initialized proc system for at least one watch");
        }
    }
    else
    {
        log_debug("No watch requiring proc system - skip initialization");
    }

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
        hash_add(nyx->state_map, watch->name, state);

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

/**
 * @brief Fire a signal using the eventfd interface
 * @param signal signal to send
 * @param nyx    nyx instance
 * @return 1 on success, 0 otherwise
 */
int
signal_eventfd(uint64_t signal, nyx_t *nyx)
{
    int error = 0;

    if (nyx->event < 1)
        return 0;

    error = write(nyx->event, &signal, sizeof(signal));

    if (error == -1)
    {
        log_perror("nyx: write");
        return 0;
    }

    return 1;
}

static void
shutdown_proc(nyx_t *nyx)
{
    /* tear down proc watch (if running) */
    if (nyx->proc_thread)
    {
        nyx_proc_terminate();
        pthread_kill(*nyx->proc_thread, SIGUSR1);
        pthread_join(*nyx->proc_thread, NULL);

        free(nyx->proc_thread);
        nyx->proc_thread = NULL;
    }

    if (nyx->proc)
    {
        nyx_proc_destroy(nyx->proc);
        nyx->proc = NULL;
    }
}

static void
clear_watches(nyx_t *nyx)
{
    if (nyx->state_map)
    {
        hash_destroy(nyx->state_map);
        nyx->state_map = NULL;
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
}

static void
destroy_plugins(nyx_t *nyx)
{
#ifdef USE_PLUGINS
    if (nyx->plugins)
    {
        log_debug("Shutdown plugins");

        plugin_repository_destroy(nyx->plugins);
        nyx->plugins = NULL;
    }

    if (nyx->options.plugins)
    {
        free((void *)nyx->options.plugins);
        nyx->options.plugins = NULL;
    }

    if (nyx->options.plugin_config)
    {
        hash_destroy(nyx->options.plugin_config);
        nyx->options.plugin_config = NULL;
    }
#endif
}

static void
destroy_options(nyx_t *nyx)
{
    if (nyx->options.log_file)
    {
        free((void *)nyx->options.log_file);
        nyx->options.log_file = NULL;
    }
}

/**
 * @brief Reload the current nyx instance configuration
 * @param nyx nyx instance to reload
 * @return 1 on success; 0 otherwise
 */
int
nyx_reload(nyx_t *nyx)
{
    log_info("Start reloading nyx");

    destroy_plugins(nyx);
    shutdown_proc(nyx);
    clear_watches(nyx);
    destroy_options(nyx);

    nyx->watches = hash_new(_watch_destroy);
    nyx->states = list_new(_state_destroy);
    nyx->state_map = hash_new(NULL);

    if (parse_config(nyx))
    {
        if (nyx_watches_init(nyx))
        {
#ifdef USE_PLUGINS
            /* load plugins if enabled */
            nyx->plugins = discover_plugins(nyx->options.plugins,
                    nyx->options.plugin_config);
#endif

            log_info("Successfully reloaded nyx");
            return 1;
        }
    }

    log_warn("Failed to reload nyx");

    return 0;
}

/**
 * @brief Destroy the nyx instance and all attached resources
 * @param nyx nyx instance to destroy
 */
void
nyx_destroy(nyx_t *nyx)
{
    int signal_sent = 0;

    if (nyx == NULL)
        return;

    /* signal termination via eventfd (if existing) */
    if (nyx->event > 0)
        signal_sent = signal_eventfd(4, nyx);

    /* tear down connector first */
    if (nyx->connector_thread)
    {
        pthread_t connector = *nyx->connector_thread;

        /* signal for termination failed
         * -> we have to force exit */
        if (!signal_sent)
            pthread_cancel(connector);

        pthread_join(connector, NULL);

        free(nyx->connector_thread);
        nyx->connector_thread = NULL;
    }

    shutdown_proc(nyx);

    clear_watches(nyx);

    destroy_plugins(nyx);

    if (nyx->options.commands)
    {
        free(nyx->options.commands);
        nyx->options.commands = NULL;
    }

    destroy_options(nyx);

    if (nyx->event > 0)
        close(nyx->event);

    if (nyx->is_daemon)
        clear_pid("nyx", nyx);

    free(nyx);
}

/* vim: set et sw=4 sts=4 tw=80: */
