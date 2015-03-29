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

#ifndef __NYX_DEF_H__
#define __NYX_DEF_H__

#include <stdlib.h>

#define NYX_VERSION_NUMBER "1.1.0"

#ifndef GIT_VERSION
#define NYX_GIT
#else
#define NYX_GIT " (" GIT_VERSION ")"
#endif

#ifndef NDEBUG
#define NYX_VERSION NYX_VERSION_NUMBER "-debug" NYX_GIT
#else
#define NYX_VERSION NYX_VERSION_NUMBER NYX_GIT
#endif

#define UNUSED __attribute__((unused))

#define LEN(x) (sizeof(x) / sizeof(x[0]))
#define MIN(a, b) ((a) > (b) ? (b) : (a))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

void *
xcalloc(size_t count, size_t size);

void *
xcalloc1(size_t size);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
