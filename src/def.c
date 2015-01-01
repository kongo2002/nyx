#include "def.h"
#include "log.h"

void *
xcalloc(size_t count, size_t size)
{
    void *ptr = calloc(count, size);

    if (ptr == NULL)
        log_critical_perror("nyx: calloc");

    return ptr;
}

/* vim: set et sw=4 sts=4 tw=80: */
