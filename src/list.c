#include "list.h"
#include "log.h"

list_t *
list_new(void (*free_func)(void *))
{
    list_t *list = calloc(1, sizeof(list_t));

    if (list == NULL)
        log_critical_perror("nyx: calloc");

    list->free_func = free_func;

    return list;
}

void
list_add(list_t *list, void *data)
{
    list_node_t *node = calloc(1, sizeof(list_node_t));

    if (node == NULL)
        log_critical_perror("nyx: calloc");

    node->data = data;

    /* empty list */
    if (list->tail == NULL)
    {
        list->head = node;
        list->tail = node;
    }
    else
    {
        list->tail->next = node;
        node->prev = list->tail;
        list->tail = node;
    }

    list->count++;
}

void
list_destroy(list_t *list)
{
    list_node_t *next = NULL;
    list_node_t *node = list->head;

    void (*free_func)(void *) = list->free_func;

    while (node)
    {
        next = node->next;

        if (free_func != NULL && node->data != NULL)
            free_func(node->data);

        free(node);
        node = next;
    }

    free(list);
    list = NULL;
}

void
list_foreach(list_t *list, void (*func)(unsigned long, void *))
{
    unsigned long i = 0;
    list_node_t *node = list->head;

    while (node)
    {
        func(i++, node->data);
        node = node->next;
    }
}

unsigned long
list_size(list_t *list)
{
    return list->count;
}

/* vim: set et sw=4 sts=4 tw=80: */
