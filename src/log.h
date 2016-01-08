/* Copyright 2014-2016 Gregor Uhlenheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __NYX_LOG_H__
#define __NYX_LOG_H__

#define _GNU_SOURCE

#include "nyx.h"

#define NYX_DEFAULT_LOG_FILE "/var/log/nyx.log"

typedef enum
{
    NYX_LOG_DEBUG    = 1 << 0,
    NYX_LOG_INFO     = 1 << 1,
    NYX_LOG_WARN     = 1 << 2,
    NYX_LOG_ERROR    = 1 << 3,
    NYX_LOG_PERROR   = 1 << 4,
    NYX_LOG_CRITICAL = 1 << 5
} log_level_e;

void
log_init(nyx_t *nyx);

void
log_shutdown(void);

void
log_message(nyx_t *nyx, log_level_e level, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

#define DECLARE_LOG_PROTO(type_, ...) \
    void log_##type_(const char* format, ...) \
        __attribute__((format(printf, 1, 2))) \
        __VA_ARGS__;

#ifndef NDEBUG
DECLARE_LOG_PROTO (debug, __attribute__(()))
#else
#define log_debug(...)
#endif

DECLARE_LOG_PROTO (info, __attribute__(()))
DECLARE_LOG_PROTO (warn, __attribute__(()))
DECLARE_LOG_PROTO (error, __attribute__(()))
DECLARE_LOG_PROTO (perror, __attribute__(()))
DECLARE_LOG_PROTO (critical, __attribute__((noreturn)))
DECLARE_LOG_PROTO (critical_perror, __attribute__((noreturn)))

#undef DECLARE_LOG_PROTO

#endif

/* vim: set et sw=4 sts=4 tw=80: */
