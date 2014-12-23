#include "list.h"

list_t *list_new(void)
{
    return calloc(1, sizeof(list_t));
}

void list_add(list_t *list, void *data)
{
    list_node_t *node = calloc(1, sizeof(list_node_t));

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

void list_destroy(list_t *list)
{
    list_node_t *next = NULL;
    list_node_t *node = list->head;

    while (node)
    {
        next = node;

        free(node);
        node = next->next;
    }

    free(list);
    list = NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
