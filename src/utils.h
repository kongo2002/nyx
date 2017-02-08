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

#pragma once

#include "list.h"

#include <stdint.h>

const char **
strings_to_null_terminated(list_t *list);

char
get_size_unit(uint64_t kbytes, uint64_t *out_bytes);

uint32_t
parse_time_unit(const char *input);

uint64_t
parse_size_unit(const char *input);

const char **
split_string(const char *str, const char *chars);

const char **
split_string_whitespace(const char *str);

const char **
parse_command_string(const char *str);

uint32_t
count_args(const char **args);

void
strings_free(char **strings);

void
wait_interval(uint32_t seconds);

void
wait_interval_fd(int32_t fd, uint32_t seconds);

/* vim: set et sw=4 sts=4 tw=80: */
