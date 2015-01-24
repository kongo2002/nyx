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
#include "tests_proc.h"
#include "../src/proc.h"

#include <stdio.h>
#include <unistd.h>

void
test_proc_system_info(UNUSED void **state)
{
    int success = 0;
    sys_info_t *info = sys_info_new();

    success = sys_info_read_proc(info, getpid());

    assert_int_not_equal(0, success);

    sys_info_dump(info);

    free(info);
}

void
test_proc_total_memory_size(UNUSED void **state)
{
    unsigned long mem_size = total_memory_size();

    assert_int_not_equal(0, mem_size);

    printf("Total memory: %lu kB\n", mem_size);
}

void
test_proc_page_size(UNUSED void **state)
{
    long page_size = get_page_size();

    assert_int_not_equal(0, page_size);

    printf("Page size: %ld\n", page_size);
}

void
test_proc_num_cpus(UNUSED void **state)
{
    int cpus = num_cpus();

    assert_true(cpus > 0);

    printf("Number of CPUs: %d\n", cpus);
}

void
test_proc_stat(UNUSED void **state)
{
    int success = 0;
    sys_proc_stat_t *stat = sys_proc_new();

    success = sys_proc_read(stat);

    assert_int_not_equal(0, success);

    sys_proc_dump(stat);

    free(stat);
}


/* vim: set et sw=4 sts=4 tw=80: */
