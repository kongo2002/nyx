#ifndef __NYX_HASH_H__
#define __NYX_HASH_H__

typedef void (*callback_t)(void *value);

typedef struct pair_t
{
    const char *key;
    void *data;
} pair_t;

typedef struct bucket_t
{
    unsigned int count;
    pair_t *pairs;
} bucket_t;

typedef struct hash_t
{
    unsigned int count;
    unsigned int bucket_count;
    bucket_t *buckets;
    callback_t free_value;

} hash_t;

typedef struct key_value_t
{
    const char *k;
    void *v;
} key_value_t;

hash_t *
hash_new(int size, callback_t free_value);

void
hash_destroy(hash_t *hash);

int
hash_add(hash_t *hash, const char *key, void *data);

void *
hash_get(hash_t *hash, const char* key);

void
hash_foreach(hash_t *hash, void (*func)(void *));

unsigned int
hash_count(hash_t *hash);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
