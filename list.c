#include "list.h"

list_t *
list_new(void)
{
    list_t *list = calloc(1, sizeof(list_t));

    if (list == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

    return list;
}

void
list_add(list_t *list, void *data)
{
    list_node_t *node = calloc(1, sizeof(list_node_t));

    if (node == NULL)
    {
        perror("nyx: calloc");
        exit(EXIT_FAILURE);
    }

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

    while (node)
    {
        next = node;

        free(node);
        node = next->next;
    }

    free(list);
    list = NULL;
}

void
list_clear(list_t *list)
{
    list_node_t *node = list->head;

    while (node)
    {
        if (node->data)
            free(node->data);
        node = node->next;
    }
}

void
list_clear_destroy(list_t *list)
{
    list_clear(list);
    list_destroy(list);
}

/* vim: set et sw=4 sts=4 tw=80: */
