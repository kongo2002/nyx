/* Copyright 2014-2018 Gregor Uhlenheuer
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

#include "def.h"
#include "log.h"
#include "timestack.h"

#include <stdio.h>
#include <string.h>

timestack_t *
timestack_new(uint32_t max)
{
    timestack_t *stack = xcalloc1(sizeof(timestack_t));

    stack->max = max;
    stack->elements = xcalloc(max, sizeof(timestack_elem_t));

    return stack;
}

void
timestack_add(timestack_t *timestack, int32_t value)
{
    time_t now = time(NULL);

    /* move all elements except the last one
     * a position further */
    uint32_t size = timestack->max;
    uint32_t count = timestack->count + 1;

    timestack->count = MIN(size, count);
    timestack_elem_t *start = timestack->elements;
    timestack_elem_t *to = start + 1;

    memmove(to, start, sizeof(timestack_elem_t) * (size - 1));

    start->value = value;
    start->time = now;
}

void
timestack_clear(timestack_t *timestack)
{
    uint32_t size = timestack->max;

    timestack->count = 0;
    memset(timestack->elements, 0, sizeof(timestack_elem_t) * size);
}

void
timestack_destroy(timestack_t *timestack)
{
    free(timestack->elements);
    free(timestack);
}

int32_t
timestack_newest(timestack_t *timestack)
{
    if (timestack->count < 1)
        return 0;

    return timestack->elements[0].value;
}

int32_t
timestack_oldest(timestack_t *timestack)
{
    uint32_t idx = timestack->count;

    if (idx < 1)
        return 0;

    return timestack->elements[idx-1].value;
}

time_t
timestack_find_latest(timestack_t *timestack, timestack_predicate_t predicate)
{
    uint32_t i = 0;
    uint32_t count = timestack->count;
    timestack_elem_t *elem = timestack->elements;

    if (count < 1)
        return 0;

    while (i++ < count)
    {
        if (predicate(elem->value))
            return elem->time;

        elem++;
    }

    return 0;
}

void
timestack_dump(timestack_t *timestack, const char* (*writer)(int32_t))
{
    uint32_t i = 0;
    uint32_t count = timestack->count;
    timestack_elem_t *elem = timestack->elements;

    if (count < 1)
        return;

    while (i++ < count)
    {
        struct tm *ltime = localtime(&elem->time);
        const char *value = writer(elem->value);

        log_info("%04d-%02d-%02dT%02d:%02d:%02d: %s",
                ltime->tm_year + 1900,
                ltime->tm_mon + 1,
                ltime->tm_mday,
                ltime->tm_hour,
                ltime->tm_min,
                ltime->tm_sec,
                value);

        elem++;
    }
}

/* vim: set et sw=4 sts=4 tw=80: */
