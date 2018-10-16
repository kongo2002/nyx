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

static void
test_parse(const char *input, const char **expected)
{
    printf("parsing command: >%s<\n", input);

    uint32_t idx = 1;
    const char **strings = parse_command_string(input);
    const char **ptr = strings;

    while (*ptr)
    {
        assert_non_null(*expected);

        printf(" %u: '%s'\n", idx++, *ptr);
        assert_string_equal(*ptr, *expected);

        free((void *)*ptr);

        ptr++;
        expected++;
    }

    assert_null(*ptr);
    assert_null(*expected);

    free(strings);
}

void
test_parse_command_string(UNUSED void **state)
{
    assert_null(parse_command_string(NULL));
    assert_null(parse_command_string(""));

    const char * array1[] = { "one", "two", "three", NULL };
    test_parse("one two three", array1);
    test_parse(" one two   three ", array1);
    test_parse(" \t one\ttwo   three ", array1);

    const char * array2[] = { "one", NULL };
    test_parse("'one'", array2);

    const char * array3[] = { "one two", NULL };
    test_parse("'one two'", array3);
    test_parse("\"one two\"", array3);

    const char * array4[] = { " one two ", NULL };
    test_parse(" ' one two ' ", array4);

    const char * array5[] = { " one two ", "three", NULL };
    test_parse(" ' one two '  three ", array5);

    const char * array6[] = { "one ' two", NULL };
    test_parse("\"one ' two\"", array6);

    const char * array7[] = { "one \" two", NULL };
    test_parse("\"one \\\" two\"", array7);

    const char * array8[] = { "one\"", NULL };
    test_parse("\"one\\\"\"", array8);

    const char * array9[] = { "\"\"", NULL };
    test_parse("\"\\\"\\\"\"", array9);

    const char * array10[] = { "one\\two", NULL };
    test_parse("one\\\\two", array10);

    const char * array11[] = { "onetwo ", "three", NULL };
    test_parse("one\"two \" three", array11);
}

static void
test_env(const char *input)
{
    char *output = NULL;
    assert_true(substitute_env_string(input, &output));

    if (output && *output)
    {
        printf("substitute_env_string: '%s' -> '%s'\n", input, output);
        free(output);
    }
}

void
test_substitute_env_string(UNUSED void **state)
{
    char *output = NULL;

    assert_false(substitute_env_string(NULL, &output));
    assert_false(substitute_env_string("", &output));
    assert_false(substitute_env_string(" $DOES_NOT_EXIST", &output));
    assert_false(substitute_env_string(" `hostname`/bar", &output));
    assert_false(substitute_env_string(" $(echo foo)/bar", &output));

    test_env("/foo/bar:/bar/foo");
    test_env("$PATH:/foo/bar");
    test_env("${PATH}:/foo/bar");
    test_env("$HOME/some/where");
    test_env("~/some/where");

    test_env("foo bar test");
    test_env("$HOME bar '$HOME' $USER");
}

/* vim: set et sw=4 sts=4 tw=80: */
