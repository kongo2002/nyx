#ifndef __NYX_LIST_H__
#define __NYX_LIST_H__

#include <stdio.h>
#include <stdlib.h>

typedef struct list_t
{
    long count;
    struct list_node_t *head;
    struct list_node_t *tail;
} list_t;

typedef struct list_node_t
{
    struct list_node_t *prev;
    struct list_node_t *next;
    void *data;
} list_node_t;

list_t *
list_new(void);

void
list_destroy(list_t *list);

void
list_clear_destroy(list_t *list);

void
list_clear(list_t *list);

void
list_add(list_t *list, void *data);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
