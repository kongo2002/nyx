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

#include "tests.h"
#include "tests_proc.h"
#include "../src/config.h"

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

static void
_free_watch(void *data)
{
    watch_t *watch = data;
    watch_destroy(watch);
}

static bool
parse_config_file(const char *name)
{
    char path[256] = {0};

    nyx_t *nyx = xcalloc1(sizeof(nyx_t));
    nyx->watches = hash_new(_free_watch);
    nyx->options.config_file = path;

    snprintf(path, LEN(path)-1, "./tests/scripts/configs/%s.yaml", name);

    bool success = parse_config(nyx, false);

    nyx_destroy(nyx);

    return success;
}

#define IMPL_TEST_CONFIG_PARSE(name_, file_) \
    static void \
    test_config_parse_##name_(UNUSED void **state) \
    { \
        assert_true(parse_config_file(file_)); \
    }

IMPL_TEST_CONFIG_PARSE(1, "single01")
IMPL_TEST_CONFIG_PARSE(2, "single02")
IMPL_TEST_CONFIG_PARSE(3, "single03")
IMPL_TEST_CONFIG_PARSE(4, "single04")
IMPL_TEST_CONFIG_PARSE(5, "single05")
IMPL_TEST_CONFIG_PARSE(6, "single06")
IMPL_TEST_CONFIG_PARSE(7, "single07")
IMPL_TEST_CONFIG_PARSE(8, "single08")
IMPL_TEST_CONFIG_PARSE(9, "single09")
IMPL_TEST_CONFIG_PARSE(10, "single10")

void
test_config_parse_files(UNUSED void **state)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(test_config_parse_1),
        cmocka_unit_test(test_config_parse_2),
        cmocka_unit_test(test_config_parse_3),
        cmocka_unit_test(test_config_parse_4),
        cmocka_unit_test(test_config_parse_5),
        cmocka_unit_test(test_config_parse_6),
        cmocka_unit_test(test_config_parse_7),
        cmocka_unit_test(test_config_parse_8),
        cmocka_unit_test(test_config_parse_9),
        cmocka_unit_test(test_config_parse_10)
    };

    assert_int_equal(0, cmocka_run_group_tests_name("config tests", tests, NULL, NULL));
}

/* vim: set et sw=4 sts=4 tw=80: */

