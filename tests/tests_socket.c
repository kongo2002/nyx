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
#include "tests_socket.h"
#include "../src/socket.h"

void
test_check_http(UNUSED void **state)
{
    if (check_port(80))
    {
        assert_int_equal(1, check_http(NULL, 80, HTTP_GET));
        assert_int_equal(0, check_http("foo/bar", 80, HTTP_GET));
    }
}

/* vim: set et sw=4 sts=4 tw=80: */
