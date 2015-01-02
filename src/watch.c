#include "def.h"
#include "fs.h"
#include "log.h"
#include "utils.h"
#include "watch.h"

#include <stdio.h>
#include <stdlib.h>

watch_t *
watch_new(const char *name)
{
    watch_t *watch = xcalloc(1, sizeof(watch_t));

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
watch_destroy(watch_t *watch)
{
    strings_free((char **)watch->start);

    if (watch->name) free((void *)watch->name);
    if (watch->uid)  free((void *)watch->uid);
    if (watch->gid)  free((void *)watch->gid);
    if (watch->dir)  free((void *)watch->dir);

    free(watch);
    watch = NULL;
}

int
watch_validate(watch_t *watch)
{
    int result = 1, valid = 0;
    uid_t uid = 0;
    gid_t gid = 0;

    result &= watch->name && *watch->name;

    if (watch->uid)
    {
        valid = get_user(watch->uid, &uid, &gid);

        if (!valid)
            log_error("Invalid uid: %s", watch->uid);

        result &= valid;
    }

    if (watch->gid)
    {
        valid = get_group(watch->gid, &uid);

        if (!valid)
            log_error("Invalid gid: %s", watch->gid);

        result &= valid;
    }

    return result;
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
