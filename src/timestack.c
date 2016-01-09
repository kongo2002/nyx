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

#include "def.h"
#include "log.h"
#include "timestack.h"

#include <stdio.h>
#include <string.h>

timestack_t *
timestack_new(unsigned max)
{
    timestack_t *stack = xcalloc1(sizeof(timestack_t));

    stack->max = max;
    stack->elements = xcalloc(max, sizeof(timestack_elem_t));

    return stack;
}

void
timestack_add(timestack_t *timestack, int value)
{
    time_t now = time(NULL);

    /* move all elements except the last one
     * a position further */
    unsigned size = timestack->max;
    unsigned count = timestack->count + 1;

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
    unsigned size = timestack->max;

    timestack->count = 0;
    memset(timestack->elements, 0, sizeof(timestack_elem_t) * size);
}

void
timestack_destroy(timestack_t *timestack)
{
    free(timestack->elements);
    free(timestack);
}

int
timestack_newest(timestack_t *timestack)
{
    if (timestack->count < 1)
        return 0;

    return timestack->elements[0].value;
}

int
timestack_oldest(timestack_t *timestack)
{
    unsigned idx = timestack->count;

    if (idx < 1)
        return 0;

    return timestack->elements[idx-1].value;
}

void
timestack_dump(timestack_t *timestack)
{
    unsigned i = 0;
    unsigned count = timestack->count;
    timestack_elem_t *elem = timestack->elements;

    if (count < 1)
        return;

    while (i++ < count)
    {
        struct tm *ltime = localtime(&elem->time);

        log_info("%04d-%02d-%02dT%02d:%02d:%02d: %d",
                ltime->tm_year + 1900,
                ltime->tm_mon + 1,
                ltime->tm_mday,
                ltime->tm_hour,
                ltime->tm_min,
                ltime->tm_sec,
                elem->value);

        elem++;
    }
}

/* vim: set et sw=4 sts=4 tw=80: */
