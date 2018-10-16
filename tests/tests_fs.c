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
#include "tests_fs.h"
#include "../src/fs.h"

static void
check_parent_dir(const char *input, const char *expected)
{
    const char *actual = parent_dir(input);

    assert_string_equal(actual, expected);

    if (actual != NULL)
        free((void *)actual);
}

void
test_fs_parent_dir(UNUSED void **state)
{
    assert_null(parent_dir("/"));
    assert_null(parent_dir("."));
    assert_null(parent_dir(".."));
    assert_null(parent_dir("../"));
    assert_null(parent_dir(NULL));
    check_parent_dir("/foo/bar/file/", "/foo/bar");
    check_parent_dir("/foo/bar/file", "/foo/bar");
    check_parent_dir("/foo/bar/", "/foo");
    check_parent_dir("/foo/bar", "/foo");
    check_parent_dir("/foo//", "/");
    check_parent_dir("/foo/", "/");
    check_parent_dir("/foo", "/");
}


void
test_fs_find_local_socket_path(UNUSED void **state)
{
    assert_null(find_local_socket_path("/"));
    assert_null(find_local_socket_path("."));
    assert_null(find_local_socket_path(".."));
    assert_null(find_local_socket_path("../"));
    assert_null(find_local_socket_path(NULL));
    assert_null(find_local_socket_path("/tmp"));
    assert_null(find_local_socket_path("/tmp/foo/bar/test"));
}

/* vim: set et sw=4 sts=4 tw=80: */
