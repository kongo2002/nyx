#include "log.h"
#include "hash.h"
#include "nyx.h"
#include "state.h"
#include "watch.h"

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
           "   -q   quiet    (output error messages only)\n"
           "   -C   no color (no terminal coloring)\n"
           "   -h   help     (print this help)\n");
    exit(EXIT_SUCCESS);
}

nyx_t *
nyx_initialize(int argc, char **args)
{
    int arg = 0, index = 0;

    nyx_t *nyx = calloc(1, sizeof(nyx_t));

    if (nyx == NULL)
        log_critical_perror("nyx: calloc");

    /* parse command line arguments */
    while ((arg = getopt(argc, args, "qCh")) != -1)
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
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(nyx->watches);

    while (hash_iter(iter, &data))
    {
        state_t *state = NULL;
        watch_t *watch = data;

        log_debug("Initialize watch '%s'", watch->name);

        state = state_new(watch, nyx);
        list_add(nyx->states, state);
    }

    free(iter);
    return 1;
}

void
nyx_destroy(nyx_t *nyx)
{
    hash_destroy(nyx->watches);
    list_destroy(nyx->states);

    free(nyx);
    nyx = NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
