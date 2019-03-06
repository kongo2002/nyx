/* Copyright 2014-2019 Gregor Uhlenheuer
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

#include "log.h"
#include "strbuf.h"

#include <stdarg.h>

#define NYX_DEFAULT_STRBUF_SIZE 8

strbuf_t *
strbuf_new(void)
{
    return strbuf_new_size(NYX_DEFAULT_STRBUF_SIZE);
}

strbuf_t *
strbuf_new_size(uint64_t initial_size)
{
    strbuf_t *str = xcalloc1(sizeof(strbuf_t));

    str->size = MAX(NYX_DEFAULT_STRBUF_SIZE, initial_size);
    str->buf = xcalloc(initial_size, sizeof(char));

    return str;
}

static uint64_t
get_new_size(strbuf_t *buf, uint64_t print_length)
{
    uint64_t new_size = buf->size;
    uint64_t min_required = buf->length + print_length + 1;

    while (new_size <= min_required)
        new_size *= 2;

    return new_size;
}

uint64_t
strbuf_append(strbuf_t *buf, const char *format, ...)
{
    if (buf == NULL)
        return 0;

    uint64_t remaining = buf->size - buf->length;

    /* immediately double size */
    if (remaining < 1)
    {
        buf->size = 2 * buf->size;

        void *new_buffer = realloc(buf->buf, buf->size * sizeof(char));

        if (new_buffer == NULL)
            log_critical_perror("nyx: realloc");

        buf->buf = new_buffer;
        remaining = buf->size - buf->length;
    }

    va_list vas;
    va_start(vas, format);

    uint64_t printed = vsnprintf(buf->buf + buf->length, remaining, format, vas);

    va_end(vas);

    /* the output was truncated */
    if (printed >= remaining)
    {
        buf->size = get_new_size(buf, printed);

        void *new_buffer = realloc(buf->buf, buf->size * sizeof(char));

        if (new_buffer == NULL)
            log_critical_perror("nyx: realloc");

        buf->buf = new_buffer;

        va_start(vas, format);
        vsnprintf(buf->buf + buf->length, buf->size - buf->length, format, vas);
        va_end(vas);
    }

    buf->length += printed;

    return printed;
}

void
strbuf_clear(strbuf_t *buf)
{
    if (buf == NULL)
        return;

    if (buf->length > 0)
        memset(buf->buf, 0, buf->size * sizeof(char));

    buf->length = 0;
}

void
strbuf_free(strbuf_t *buf)
{
    if (buf == NULL)
        return;

    if (buf->buf)
        free(buf->buf);

    free(buf);
}

/* vim: set et sw=4 sts=4 tw=80: */
