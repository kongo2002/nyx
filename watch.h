#ifndef __NYX_WATCH_H__
#define __NYX_WATCH_H__

typedef struct watch_t
{
    const char *name;
} watch_t;

watch_t *
watch_new(const char *name);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
