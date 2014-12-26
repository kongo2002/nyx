#include "log.h"
#include "nyx.h"
#include "map.h"

#include <stdlib.h>
#include <stdio.h>

nyx_t *
nyx_initialize(const char *config)
{
    nyx_t *nyx = calloc(1, sizeof(nyx_t));

    if (nyx == NULL)
    {
        log_perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    nyx->config_file = config;
    nyx->watches = hash_new(8);

    return nyx;
}

void
nyx_destroy(nyx_t *nyx)
{
    hash_destroy(nyx->watches);

    free(nyx);
    nyx = NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
