#include "watch.h"

#include <stdio.h>
#include <stdlib.h>

watch_t *
watch_new(const char *name)
{
    watch_t *watch = calloc(1, sizeof(watch_t));

    if (watch == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    watch->name = name;

    return watch;
}

/* vim: set et sw=4 sts=4 tw=80: */
