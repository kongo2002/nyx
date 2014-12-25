#include "map.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAP_KEY_MAXLEN 100

static unsigned long
hash_string(const char *str)
{
    int c;
    unsigned long hash = 5381;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

hash_t *
hash_new(int size)
{
    hash_t *hash = calloc(1, sizeof(hash_t));

    if (hash == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    size = size > 0 ? size : 4;

    hash->count = size;
    hash->buckets = calloc(size, sizeof(bucket_t));

    if (hash->buckets == NULL)
    {
        perror("nyx: calloc");
        free(hash);
        exit(EXIT_FAILURE);
    }

    return hash;
}

static pair_t *
get_pair(bucket_t *bucket, const char *key)
{
    unsigned int i = 0;
    unsigned int count = bucket->count;
    pair_t *pair = NULL;

    if (count < 1)
        return NULL;

    pair = bucket->pairs;

    while (i < count)
    {
        if (pair->key != NULL &&
            strncmp(pair->key, key, MAP_KEY_MAXLEN) == 0)
            return pair;

        pair++; i++;
    }

    return NULL;
}

static void
bucket_destroy(bucket_t *bucket)
{
    unsigned int i = 0;
    unsigned int count = bucket->count;
    pair_t *pair = NULL;

    if (count < 1)
        return;

    pair = bucket->pairs;

    while (i < count)
    {
        free((void *)pair->key);

        pair++; i++;
    }

    free(bucket->pairs);
}

void
hash_destroy(hash_t *hash)
{
    unsigned int i = 0, count = 0;
    bucket_t *bucket = NULL;

    if (hash == NULL)
        return;

    bucket = hash->buckets;
    count = hash->count;

    while (i < count)
    {
        bucket_destroy(bucket);

        bucket++; i++;
    }

    free(hash->buckets);
    free(hash);
}

static bucket_t *
get_bucket(hash_t *hash, const char *key)
{
    unsigned long keyhash = hash_string(key);

    return &(hash->buckets[keyhash % hash->count]);
}

int
hash_add(hash_t *hash, const char *key, void *data)
{
    size_t keylen, len;
    unsigned int bucket_count;
    char *key_cpy = NULL;

    bucket_t *bucket = NULL;
    pair_t *pair = NULL;

    if (hash == NULL || key == NULL)
        return 0;

    bucket = get_bucket(hash, key);
    pair = get_pair(bucket, key);

    /* there is already a matching pair in the current bucket */
    if (pair != NULL)
        return 0;

    bucket_count = bucket->count;

    /* the bucket is empty */
    if (bucket_count < 1)
    {
        bucket->pairs = calloc(1, sizeof(pair_t));

        if (bucket->pairs == NULL)
        {
            perror("nyx: calloc");
            exit(EXIT_FAILURE);
        }

        pair = bucket->pairs;
    }
    /* reallocate the existing bucket */
    else
    {
        bucket->pairs = realloc(bucket->pairs, sizeof(pair_t) * (bucket_count + 1));
        pair = &(bucket->pairs[bucket_count]);
    }

    /* determine maximum key length */
    keylen = strlen(key);
    len = keylen > MAP_KEY_MAXLEN ? MAP_KEY_MAXLEN : keylen;

    /* copy and assign key */
    key_cpy = calloc(len+1, sizeof(char));
    strncpy(key_cpy, key, len);

    pair->key = key_cpy;
    pair->data = data;

    bucket->count++;

    return 1;
}

void *
hash_get(hash_t *hash, const char* key)
{
    bucket_t *bucket = NULL;
    pair_t *pair = NULL;

    if (hash == NULL || key == NULL)
        return NULL;

    bucket = get_bucket(hash, key);
    pair = get_pair(bucket, key);

    if (pair == NULL)
        return NULL;

    return pair->data;
}

hash_t *
hash_from_array(key_value_t key_values[], int size)
{
    hash_t *hash = NULL;
    key_value_t *kv = NULL;

    if (key_values == NULL)
        return NULL;

    kv = key_values;
    hash = hash_new(size);

    while (kv && kv->k)
    {
        hash_add(hash, kv->k, kv->v);
        kv++;
    }

    return hash;
}

/* vim: set et sw=4 sts=4 tw=80: */
