/* Copyright 2014-2016 Gregor Uhlenheuer
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

#include "def.h"

#include <stdint.h>

typedef struct
{
    char *buf;
    uint64_t size;
    uint64_t length;
} strbuf_t;

strbuf_t *
strbuf_new(void);

strbuf_t *
strbuf_new_size(uint64_t initial_size);

uint64_t
strbuf_append(strbuf_t *buf, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

void
strbuf_free(strbuf_t *buf);

void
strbuf_clear(strbuf_t *buf);

/* vim: set et sw=4 sts=4 tw=80: */
