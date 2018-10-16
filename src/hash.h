/* Copyright 2014-2018 Gregor Uhlenheuer
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

#include <stdbool.h>
#include <stdint.h>

typedef void (*callback_t)(void *value);

typedef bool (*filter_callback_t)(void *value);

typedef struct
{
    const char *key;
    void *data;
} pair_t;

typedef struct
{
    uint32_t count;
    pair_t *pairs;
} bucket_t;

typedef struct
{
    uint32_t count;
    uint32_t bucket_count;
    bucket_t *buckets;
    callback_t free_value;

} hash_t;

typedef struct
{
    const char *k;
    void *v;
} key_value_t;

typedef struct
{
    hash_t *_hash;
    uint32_t _bucket;
    uint32_t _pair;
} hash_iter_t;

hash_t *
hash_new(callback_t free_value);

hash_t *
hash_new_initial(uint32_t initial_size, callback_t free_value);

void
hash_destroy(hash_t *hash);

bool
hash_add(hash_t *hash, const char *key, void *data);

void *
hash_get(hash_t *hash, const char* key);

hash_iter_t *
hash_iter_start(hash_t *hash);

void
hash_iter_rewind(hash_iter_t *iter);

bool
hash_iter(hash_iter_t *iter, const char **key, void **data);

void
hash_foreach(hash_t *hash, void (*func)(void *));

uint32_t
hash_count(hash_t *hash);

bool
hash_remove(hash_t *hash, const char *key);

uint32_t
hash_filter(hash_t *hash, filter_callback_t filter_func);

/* vim: set et sw=4 sts=4 tw=80: */
