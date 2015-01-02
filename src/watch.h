#ifndef __NYX_WATCH_H__
#define __NYX_WATCH_H__

typedef struct watch_t
{
    const char *name;
    const char *uid;
    const char *gid;
    const char **start;
    const char *dir;
} watch_t;

watch_t *
watch_new(const char *name);

void
watch_dump(watch_t *watch);

void
watch_destroy(watch_t *watch);

int
watch_validate(watch_t *watch);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
