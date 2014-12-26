#ifndef __NYX_H__
#define __NYX_H__

#include "map.h"

typedef struct
{
    const char *config_file;
    hash_t *watches;
} nyx_t;

nyx_t *
nyx_initialize(const char *config);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
