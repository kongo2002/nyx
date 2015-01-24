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

#ifndef __NYX_UTILS_H__
#define __NYX_UTILS_H__

#include "list.h"

const char **
strings_to_null_terminated(list_t *list);

char
get_size_unit(unsigned long kbytes, unsigned long *out_bytes);

const char **
split_string(const char *string);

void
strings_free(char **strings);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
