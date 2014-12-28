#include "log.h"
#include "watch.h"

#include <stdio.h>
#include <stdlib.h>

watch_t *
watch_new(const char *name)
{
    watch_t *watch = calloc(1, sizeof(watch_t));

    if (watch == NULL)
        log_critical_perror("nyx: calloc");

    watch->name = name;

    return watch;
}

static void
dump_not_empty(const char *key, const char *value)
{
    if (value == NULL || *value == '\0')
        return;

    log_info("  %s: %s", key, value);
}

static void
dump_strings(const char *key, const char **values)
{
    const char **value;

    if (values == NULL || *values == NULL)
        return;

    log_info("  %s: [", key);

    value = values;

    while (*value)
    {
        log_info("   '%s'", *value);
        value++;
    }

    log_info("   ]");
}

void
watch_dump(watch_t *watch)
{
    log_info("Watch '%s'", watch->name);

    dump_strings("start", watch->start);
    dump_not_empty("uid", watch->uid);
    dump_not_empty("gid", watch->gid);
    dump_not_empty("dir", watch->dir);
}

/* vim: set et sw=4 sts=4 tw=80: */
