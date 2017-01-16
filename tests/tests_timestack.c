/* Copyright 2014-2017 Gregor Uhlenheuer
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

#include "tests.h"
#include "tests_timestack.h"
#include "../src/timestack.h"

#include <string.h>

void
test_timestack_create(UNUSED void **state)
{
    timestack_t *timestack = timestack_new(4);

    assert_int_equal(0, timestack->count);

    timestack_destroy(timestack);
}

void
test_timestack_add(UNUSED void **state)
{
    uint32_t count = 100;

    timestack_t *timestack = timestack_new(4);

    assert_int_equal(0, timestack->count);

    for (uint32_t i = 0; i < count; i++)
    {
        timestack_add(timestack, i);
    }

    assert_int_equal(4, timestack->count);

    assert_int_equal(96, timestack_oldest(timestack));
    assert_int_equal(99, timestack_newest(timestack));

    timestack_destroy(timestack);
}

/* vim: set et sw=4 sts=4 tw=80: */
