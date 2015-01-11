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
#include "tests_hash.h"

int
main(UNUSED int argc, UNUSED char **argv)
{
    const UnitTest tests[] =
    {
        unit_test(test_list_create),
        unit_test(test_list_add),
        unit_test(test_hash_create),
        unit_test(test_hash_add)
    };

    return run_tests(tests);
}

/* vim: set et sw=4 sts=4 tw=80: */
