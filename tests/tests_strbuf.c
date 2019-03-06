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
#include "tests_strbuf.h"
#include "../src/strbuf.h"

void
test_strbuf_append(UNUSED void **state)
{
    strbuf_t *buf = strbuf_new();

    strbuf_append(buf, "foo %s", "bar");
    assert_string_equal(buf->buf, "foo bar");

    strbuf_append(buf, " ham");
    assert_string_equal(buf->buf, "foo bar ham");

    strbuf_append(buf, " eggs");
    assert_string_equal(buf->buf, "foo bar ham eggs");

    strbuf_append(buf, " %d", 521);
    assert_string_equal(buf->buf, "foo bar ham eggs 521");

    strbuf_clear(buf);

    strbuf_append(buf, "%s %s %s %s", "foo", "bar", "ham", "eggs");
    assert_string_equal(buf->buf, "foo bar ham eggs");

    strbuf_free(buf);
}

/* vim: set et sw=4 sts=4 tw=80: */
