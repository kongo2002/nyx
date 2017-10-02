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

#define _GNU_SOURCE

#include "tests.h"
#include "tests_hash.h"
#include "../src/hash.h"

#include <stdio.h>
#include <string.h>

void
test_hash_create(UNUSED void **state)
{
    hash_t *hash = hash_new(free);

    assert_int_equal(0, hash_count(hash));

    hash_destroy(hash);
}

void
test_hash_add(UNUSED void **state)
{
    uint32_t size = 512;
    char buffer[512] = {0};

    hash_t *hash = hash_new(free);

    assert_int_equal(0, hash_count(hash));

    for (uint32_t i = 0; i < size; i++)
    {
        sprintf(buffer, "value%u", i);
        char *value = strdup(buffer);

        sprintf(buffer, "key%u", i);
        assert_true(hash_add(hash, buffer, value));
    }

    assert_int_equal(size, hash_count(hash));

    for (uint32_t i = 0; i < size; i++)
    {
        sprintf(buffer, "key%u", i);
        char *value = hash_get(hash, buffer);

        assert_non_null(value);

        sprintf(buffer, "value%u", i);
        assert_string_equal(buffer, value);
    }

    /* test for duplicate entries */
    assert_int_equal(0, hash_add(hash, "key0", "value0"));

    hash_destroy(hash);
}

void
test_hash_remove(UNUSED void **state)
{
    uint32_t size = 10;
    char buffer[512] = {0};

    hash_t *hash = hash_new(free);

    assert_int_equal(0, hash_count(hash));

    /* fill hash with some values */
    for (uint32_t i = 0; i < size; i++)
    {
        sprintf(buffer, "value%u", i);
        char *value = strdup(buffer);

        sprintf(buffer, "key%u", i);
        assert_true(hash_add(hash, buffer, value));
    }

    assert_int_equal(size, hash_count(hash));

    /* remove two values */
    assert_true(hash_remove(hash, "key2"));
    assert_true(hash_remove(hash, "key4"));

    /* check size */
    assert_int_equal(size - 2, hash_count(hash));

    /* check removal of non-existing keys */
    assert_false(hash_remove(hash, "non-existing"));
    assert_false(hash_remove(hash, "key2"));

    assert_int_equal(size - 2, hash_count(hash));

    hash_destroy(hash);
}


/* vim: set et sw=4 sts=4 tw=80: */
