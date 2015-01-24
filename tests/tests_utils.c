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
#include "tests_utils.h"
#include "../src/utils.h"

void
test_parse_size_unit(UNUSED void **state)
{
    assert_true(25 == parse_size_unit(" 25"));
    assert_true(25 == parse_size_unit(" 25 "));
    assert_true(25 == parse_size_unit("25"));
    assert_true(25 == parse_size_unit("25k"));
    assert_true(25 == parse_size_unit("25 k"));
    assert_true(25 == parse_size_unit("25 K"));
    assert_true(25 == parse_size_unit("25 Kb "));

    assert_true(1024 == parse_size_unit("1 Mb "));
    assert_true(1024 == parse_size_unit("1Mb "));
    assert_true(1024 == parse_size_unit(" 1 mb "));
    assert_true(20480 == parse_size_unit(" 20 m "));

    assert_true(2097152 == parse_size_unit("2G"));

    assert_true(2097152 == parse_size_unit("2G"));

    assert_int_equal(0, parse_size_unit("226X"));
    assert_int_equal(0, parse_size_unit("226 x"));
    assert_int_equal(0, parse_size_unit("x 226"));
}

/* vim: set et sw=4 sts=4 tw=80: */
