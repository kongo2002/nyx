#ifndef __NYX_H__
#define __NYX_H__

#include "map.h"

typedef struct
{
    int quiet;
    int no_color;
    const char *filename;
} nyx_options_t;

typedef struct
{
    nyx_options_t options;
    hash_t *watches;
} nyx_t;

nyx_t *
nyx_initialize(int argc, char **args);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
