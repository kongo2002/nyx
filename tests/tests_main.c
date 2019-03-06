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
#include "tests_config.h"
#include "tests_fs.h"
#include "tests_hash.h"
#include "tests_list.h"
#include "tests_proc.h"
#include "tests_socket.h"
#include "tests_strbuf.h"
#include "tests_timestack.h"
#include "tests_utils.h"
#include "tests_watch.h"

int
main(UNUSED int argc, UNUSED char **argv)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(test_config_parse_files),
        cmocka_unit_test(test_list_create),
        cmocka_unit_test(test_list_add),
        cmocka_unit_test(test_list_pop),
        cmocka_unit_test(test_list_pop_empty),
        cmocka_unit_test(test_hash_create),
        cmocka_unit_test(test_hash_add),
        cmocka_unit_test(test_hash_remove),
        cmocka_unit_test(test_timestack_create),
        cmocka_unit_test(test_timestack_add),
        cmocka_unit_test(test_fs_parent_dir),
        cmocka_unit_test(test_fs_find_local_socket_path),
        cmocka_unit_test(test_fs_create_if_not_exists),
        cmocka_unit_test(test_proc_system_info),
        cmocka_unit_test(test_proc_total_memory_size),
        cmocka_unit_test(test_proc_stat),
        cmocka_unit_test(test_proc_num_cpus),
        cmocka_unit_test(test_proc_page_size),
        cmocka_unit_test(test_parse_size_unit),
        cmocka_unit_test(test_parse_command_string),
        cmocka_unit_test(test_substitute_env_string),
        cmocka_unit_test(test_check_http),
        cmocka_unit_test(test_strbuf_append),
        cmocka_unit_test(test_is_all)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* vim: set et sw=4 sts=4 tw=80: */
