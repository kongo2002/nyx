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

#include "def.h"
#include "hash.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NYX_HASH_MAX_FACTOR 1.3
#define NYX_HASH_INITIAL_SIZE 8
#define NYX_HASH_KEY_MAXLEN 100

static uint64_t
hash_string(const char *str)
{
    int32_t c;
    uint64_t hash = 5381;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

hash_t *
hash_new_initial(uint32_t initial_size, callback_t free_value)
{
    hash_t *hash = xcalloc1(sizeof(hash_t));

    initial_size = initial_size > 0 ? initial_size : NYX_HASH_INITIAL_SIZE;

    hash->bucket_count = initial_size;
    hash->buckets = xcalloc(initial_size, sizeof(bucket_t));
    hash->free_value = free_value;

    return hash;
}

hash_t *
hash_new(callback_t free_value)
{
    return hash_new_initial(NYX_HASH_INITIAL_SIZE, free_value);
}

static pair_t *
get_pair(bucket_t *bucket, const char *key, uint32_t *idx)
{
    *idx = 0;
    uint32_t count = bucket->count;
    pair_t *pair = NULL;

    if (count < 1)
        return NULL;

    pair = bucket->pairs;

    while (*idx < count)
    {
        if (pair->key != NULL &&
            strncmp(pair->key, key, NYX_HASH_KEY_MAXLEN) == 0)
            return pair;

        pair++; (*idx)++;
    }

    return NULL;
}

static void
bucket_destroy(bucket_t *bucket, callback_t free_func)
{
    uint32_t i = 0;
    uint32_t count = bucket->count;
    pair_t *pair = NULL;

    if (count < 1)
        return;

    pair = bucket->pairs;

    while (i < count)
    {
        free((void *)pair->key);

        if (free_func != NULL && pair->data != NULL)
            free_func(pair->data);

        pair++; i++;
    }

    free(bucket->pairs);
}

void
hash_destroy(hash_t *hash)
{
    uint32_t i = 0, count = 0;
    bucket_t *bucket = NULL;

    if (hash == NULL)
        return;

    bucket = hash->buckets;
    count = hash->bucket_count;

    while (i < count)
    {
        bucket_destroy(bucket, hash->free_value);

        bucket++; i++;
    }

    free(hash->buckets);
    free(hash);
}

uint32_t
hash_count(hash_t *hash)
{
    if (hash == NULL)
        return 0;

    return hash->count;
}

static bucket_t *
get_bucket(hash_t *hash, const char *key)
{
    uint64_t keyhash = hash_string(key);

    return &(hash->buckets[keyhash % hash->bucket_count]);
}

static void
rehash(hash_t* hash)
{
    uint32_t i = 0;
    uint32_t old_bucket_count = hash->bucket_count;
    hash->bucket_count = old_bucket_count * 2;

    bucket_t *old_bucket = hash->buckets;
    bucket_t *old_buckets = hash->buckets;

    hash->buckets = xcalloc(hash->bucket_count, sizeof(bucket_t));

    /* iterate old buckets */
    while (i < old_bucket_count)
    {
        uint32_t j = 0, pairs = old_bucket->count;
        pair_t *pair = old_bucket->pairs;

        while (j < pairs)
        {
            /* find new bucket */
            bucket_t *new_bucket = get_bucket(hash, pair->key);

            if (new_bucket->count < 1)
            {
                new_bucket->pairs = xcalloc1(sizeof(pair_t));
            }
            else
            {
                new_bucket->pairs = realloc(new_bucket->pairs,
                        sizeof(pair_t) * (new_bucket->count + 1));
            }

            memmove(&new_bucket->pairs[new_bucket->count],
                    pair, sizeof(pair_t));

            new_bucket->count++;

            j++; pair++;
        }

        if (old_bucket->pairs)
            free(old_bucket->pairs);

        i++; old_bucket++;
    }

    free(old_buckets);
}

bool
hash_add(hash_t *hash, const char *key, void *data)
{
    uint32_t idx = 0;

    bucket_t *bucket = NULL;
    pair_t *pair = NULL;

    if (hash == NULL || key == NULL)
        return false;

    bucket = get_bucket(hash, key);
    pair = get_pair(bucket, key, &idx);

    /* there is already a matching pair in the current bucket */
    if (pair != NULL)
        return false;

    uint32_t bucket_count = bucket->count;

    /* the bucket is empty */
    if (bucket_count < 1)
    {
        bucket->pairs = xcalloc(1, sizeof(pair_t));

        pair = bucket->pairs;
    }
    /* reallocate the existing bucket */
    else
    {
        bucket->pairs = realloc(bucket->pairs, sizeof(pair_t) * (bucket_count + 1));
        pair = &(bucket->pairs[bucket_count]);
    }

    /* determine maximum key length */
    size_t keylen = strlen(key);
    size_t len = keylen > NYX_HASH_KEY_MAXLEN ? NYX_HASH_KEY_MAXLEN : keylen;

    /* copy and assign key */
    char *key_cpy = xcalloc(len+1, sizeof(char));
    strncpy(key_cpy, key, len);

    pair->key = key_cpy;
    pair->data = data;

    bucket->count++;
    hash->count++;

    double factor = (double)(hash->count) / hash->bucket_count;
    if (factor >= NYX_HASH_MAX_FACTOR)
        rehash(hash);

    return true;
}

void *
hash_get(hash_t *hash, const char* key)
{
    uint32_t idx = 0;

    if (hash == NULL || key == NULL)
        return NULL;

    bucket_t *bucket = get_bucket(hash, key);
    pair_t *pair = get_pair(bucket, key, &idx);

    if (pair == NULL)
        return NULL;

    return pair->data;
}

bool
hash_remove(hash_t *hash, const char *key)
{
    if (hash == NULL || key == NULL)
        return false;

    bucket_t *bucket = get_bucket(hash, key);

    if (bucket == NULL)
        return false;

    uint32_t idx = 0;
    pair_t *pair = get_pair(bucket, key, &idx);

    if (pair == NULL)
        return false;

    /* free key and value memory */
    free((char *)pair->key);
    hash->free_value(pair->data);

    hash->count--;
    bucket->count--;

    pair_t *new_pairs = bucket->count
        ? xcalloc(bucket->count, sizeof(pair_t))
        : NULL;

    for (uint32_t i = 0; i<bucket->count+1; i++)
    {
        if (i == idx)
            continue;

        pair = &bucket->pairs[i];

        uint32_t j = i > idx ? i-1 : i;

        new_pairs[j].key = pair->key;
        new_pairs[j].data = pair->data;
    }

    free(bucket->pairs);
    bucket->pairs = new_pairs;

    return true;
}

static void
hash_iter_init(hash_iter_t *iter, hash_t *hash)
{
    iter->_hash = hash;
    iter->_pair = 0;
    iter->_bucket = 0;

    while (hash->bucket_count > iter->_bucket &&
            hash->buckets[iter->_bucket].count == 0)
    {
        iter->_bucket += 1;
    }
}

hash_iter_t *
hash_iter_start(hash_t *hash)
{
    hash_iter_t *iter = xcalloc1(sizeof(hash_iter_t));

    hash_iter_init(iter, hash);

    return iter;
}

void
hash_iter_rewind(hash_iter_t *iter)
{
    hash_iter_init(iter, iter->_hash);
}

bool
hash_iter(hash_iter_t *iter, const char **key, void **data)
{
    if (iter == NULL || iter->_hash == NULL)
        return false;

    const hash_t *hash = iter->_hash;

    if (hash->bucket_count <= iter->_bucket)
        return false;

    const bucket_t *bucket = hash->buckets + iter->_bucket;

    if (bucket == NULL ||
            (bucket->count <= iter->_pair && hash->bucket_count <= iter->_bucket))
        return false;

    *key = bucket->pairs[iter->_pair].key;
    *data = bucket->pairs[iter->_pair].data;

    /* proceed iterator */
    if ((iter->_pair + 1) >= bucket->count)
    {
        do
        {
            iter->_bucket += 1;
        }
        while (hash->bucket_count > iter->_bucket &&
                hash->buckets[iter->_bucket].count == 0);

        iter->_pair = 0;
    }
    else
        iter->_pair += 1;

    return true;
}

uint32_t
hash_filter(hash_t *hash, filter_callback_t filter_func)
{
    if (hash == NULL || filter_func == NULL)
        return 0;

    uint32_t filtered = 0;
    const char *key = NULL;
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(hash);

    while (hash_iter(iter, &key, &data))
    {
        /* predicate matches -> remove */
        if (filter_func(data))
        {
            if (hash_remove(hash, key))
            {
                hash_iter_rewind(iter);
                filtered++;
            }
        }
    }

    free(iter);

    return filtered;
}

void
hash_foreach(hash_t *hash, void (*func)(void *))
{
    uint32_t i = 0;
    uint32_t bucket_count = hash->bucket_count;

    bucket_t *bucket = hash->buckets;

    while (i < bucket_count)
    {
        uint32_t j = 0, pairs = bucket->count;
        pair_t *pair = bucket->pairs;

        while (j < pairs)
        {
            if (pair->data != NULL)
                func(pair->data);

            pair++; j++;
        }

        bucket++; i++;
    }
}

/* vim: set et sw=4 sts=4 tw=80: */
