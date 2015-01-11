/* Copyright 2014-2015 Gregor Uhlenheuer
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
#include "tests_list.h"
#include "../src/list.h"

#include <string.h>

void
test_list_create(UNUSED void **state)
{
    list_t *list = list_new(free);

    assert_int_equal(0, list_size(list));

    list_destroy(list);
}

void
test_list_add(UNUSED void **state)
{
    int i = 0, size = 100;

    list_t *list = list_new(free);

    assert_int_equal(0, list_size(list));

    for (i = 0; i < size; i++)
    {
        list_add(list, strdup("foo"));
    }

    assert_int_equal(size, list_size(list));

    list_destroy(list);
}

/* vim: set et sw=4 sts=4 tw=80: */
