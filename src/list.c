/* Copyright 2014-2015 Gregor Uhlenheuer
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
#include "list.h"
#include "log.h"

list_t *
list_new(void (*free_func)(void *))
{
    list_t *list = xcalloc(1, sizeof(list_t));

    list->free_func = free_func;

    return list;
}

void
list_add(list_t *list, void *data)
{
    list_node_t *node = xcalloc(1, sizeof(list_node_t));

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
