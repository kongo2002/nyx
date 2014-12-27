#ifndef __NYX_LOG_H__
#define __NYX_LOG_H__

#define _GNU_SOURCE

#include "nyx.h"

typedef enum
{
    LOG_DEBUG    = 1 << 0,
    LOG_INFO     = 1 << 1,
    LOG_WARN     = 1 << 2,
    LOG_ERROR    = 1 << 3,
    LOG_PERROR   = 1 << 4,
    LOG_CRITICAL = 1 << 5
} log_level_e;

void
log_init(nyx_t *nyx);

#define DECLARE_LOG_PROTO(type_) \
void log_##type_(const char* format, ...);

#ifndef NDEBUG
DECLARE_LOG_PROTO (debug)
#else
#define log_debug(fmt, ...)
#endif

DECLARE_LOG_PROTO (info)
DECLARE_LOG_PROTO (warn)
DECLARE_LOG_PROTO (error)
DECLARE_LOG_PROTO (perror)
DECLARE_LOG_PROTO (critical)
DECLARE_LOG_PROTO (critical_perror)

#undef DECLARE_LOG_PROTO

#endif

/* vim: set et sw=4 sts=4 tw=80: */
