#include "hash.h"
#include "log.h"
#include "nyx.h"
#include "state.h"
#include "watch.h"

#include <getopt.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static void
_watch_destroy(void *watch)
{
    watch_destroy((watch_t *)watch);
}

static void
_state_destroy(void *state)
{
    state_destroy((void *)state);
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
    printf("\n"
           "Options:\n"
           "   -q  --quiet    (output error messages only)\n"
           "   -C  --no-color (no terminal coloring)\n"
           "   -h  --help     (print this help)\n");
    exit(EXIT_SUCCESS);
}

static const struct option long_options[] =
{
    { .name = "help",     .has_arg = 0, .flag = NULL, .val = 'h'},
    { .name = "no-color", .has_arg = 0, .flag = NULL, .val = 'C'},
    { .name = "quiet",    .has_arg = 0, .flag = NULL, .val = 'q'},
    { NULL }
};

nyx_t *
nyx_initialize(int argc, char **args)
{
    int arg = 0, index = 0;

    nyx_t *nyx = calloc(1, sizeof(nyx_t));

    if (nyx == NULL)
        log_critical_perror("nyx: calloc");

    /* parse command line arguments */
    while ((arg = getopt_long(argc, args, "qCh", long_options, NULL)) != -1)
    {
        switch (arg)
        {
            case 'q':
                nyx->options.quiet = 1;
                break;
            case 'C':
                nyx->options.no_color = 1;
                break;
            case 'h':
                print_help();
                break;
        }
    }

    for (index = optind; index < argc; )
    {
        /* TODO: support multiple config files */
        nyx->options.filename = args[index];
        break;
    }

    log_init(nyx);

    nyx->pid = getpid();
    nyx->watches = hash_new(8, _watch_destroy);
    nyx->states = list_new(_state_destroy);

    return nyx;
}

int
nyx_watches_init(nyx_t *nyx)
{
    int rc = 1, init = 0;
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(nyx->watches);

    while (hash_iter(iter, &data))
    {
        state_t *state = NULL;
        watch_t *watch = data;

        log_debug("Initialize watch '%s'", watch->name);

        /* create new state instance */
        state = state_new(watch, nyx);
        list_add(nyx->states, state);

        /* start a new thread for each state */
        state->thread = calloc(1, sizeof(pthread_t));

        if (state->thread == NULL)
            log_critical_perror("nyx: calloc");

        /* create with default thread attributes */
        init = pthread_create(state->thread, NULL, state_loop_start, state);
        if (init != 0)
        {
            log_error("Failed to create thread, error: %d", init);
            rc = 0;
            break;
        }
    }

    free(iter);
    return rc;
}

void
nyx_destroy(nyx_t *nyx)
{
    log_debug("Tearing down nyx");

    list_destroy(nyx->states);
    hash_destroy(nyx->watches);

    free(nyx);
    nyx = NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
