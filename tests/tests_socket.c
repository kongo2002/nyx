/* Copyright 2014-2019 Gregor Uhlenheuer
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
    if (check_local_port(80))
    {
        assert_int_equal(1, check_http(NULL, 80, HTTP_GET));
        assert_int_equal(0, check_http("foo/bar", 80, HTTP_GET));
    }
}

void
test_check_port(UNUSED void **state)
{
    assert_true(check_port("google.com", 80));
    assert_true(check_port("google.com", 443));
    assert_false(check_port("ab.cd.ef.gh", 10000));
}

void
test_parse_endpoint(UNUSED void **state)
{
    assert_null(parse_endpoint(NULL));
    assert_null(parse_endpoint(""));
    assert_null(parse_endpoint("foo"));

    endpoint_t *e1 = parse_endpoint("127.0.0.1:80");
    assert_non_null(e1);
    assert_string_equal(e1->host, "127.0.0.1");
    assert_int_equal(e1->port, 80);

    endpoint_free(e1);

    endpoint_t *e2 = parse_endpoint("27017");
    assert_non_null(e2);
    assert_null(e2->host);
    assert_int_equal(e2->port, 27017);

    endpoint_free(e2);
}

/* vim: set et sw=4 sts=4 tw=80: */
