#include "log.h"
#include "nyx.h"

#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int quiet = 0;
static volatile int color = 1;

void
log_init(nyx_t *nyx)
{
#ifndef NDEBUG
    quiet = 0;
#else
    quiet = nyx->options.quiet;
#endif

    color = !nyx->options.no_color;
}

static const char *
get_log_color(log_level_e level, size_t *length)
{
    const char *color;

    if (level & LOG_INFO)
        color = "\033[36m";
    else if (level & LOG_WARN)
        color = "\033[33m";
    else if (level & LOG_CRITICAL)
        color = "\033[31;1m";
    else if (level & LOG_DEBUG)
        color = "\033[37m";
    else if (level & LOG_PERROR)
        color = "\033[35m";
    else
        color = "\033[32m";

    *length = strlen(color);

    return color;
}

static void
log_msg(log_level_e level, const char *msg, size_t length)
{
    static const size_t end_length = 4;
    static const char *end_color= "\033[0m";

    /* safe errno */
    int error = errno;

    if (color)
    {
        size_t start_length;
        const char *start_color = get_log_color(level, &start_length);

        fwrite(start_color, start_length, 1, stdout);
    }

    fwrite(msg, length, 1, stdout);

    /* errno specific handling */
    if (level & LOG_PERROR)
    {
        char buffer[512];
        char *error_msg = strerror_r(error, buffer, 511);

        fputc(':', stdout);
        fputc(' ', stdout);
        fwrite(error_msg, strlen(error_msg), 1, stdout);
    }

    if (color)
        fwrite(end_color, end_length, 1, stdout);

    fputc('\n', stdout);

    /* restore errno? */
    /* errno = error; */
}

static void
log_format_msg(log_level_e level, const char *format, va_list values)
{
    char *msg;

    int length = vasprintf(&msg, format, values);

    if (length > 0)
    {
        log_msg(level, msg, length);
        free(msg);
    }
}

#define DECLARE_LOG_FUNC(fn_, level_) \
    void \
    log_##fn_(const char *format, ...) \
    { \
        if (quiet) return; \
        va_list vas; \
        va_start(vas, format); \
        log_format_msg(level_, format, vas); \
        va_end(vas); \
        if ((level_) & LOG_CRITICAL) abort(); \
    }

#ifndef NDEBUG
DECLARE_LOG_FUNC (debug,           LOG_DEBUG)
#endif

DECLARE_LOG_FUNC (info,            LOG_INFO)
DECLARE_LOG_FUNC (warn,            LOG_WARN)
DECLARE_LOG_FUNC (error,           LOG_ERROR)
DECLARE_LOG_FUNC (perror,          LOG_PERROR)
DECLARE_LOG_FUNC (critical,        LOG_CRITICAL)
DECLARE_LOG_FUNC (critical_perror, LOG_CRITICAL | LOG_PERROR)

#undef DECLARE_LOG_FUNC

/* vim: set et sw=4 sts=4 tw=80: */
