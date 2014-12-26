#ifndef __NYX_MAP_H__
#define __NYX_MAP_H__

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

} hash_t;

typedef struct key_value_t
{
    const char *k;
    void *v;
} key_value_t;

hash_t *
hash_new(int size);

void
hash_destroy(hash_t *hash);

int
hash_add(hash_t *hash, const char *key, void *data);

void *
hash_get(hash_t *hash, const char* key);

hash_t *
hash_from_array(key_value_t key_values[], int size);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
