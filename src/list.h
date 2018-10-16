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
#include <stdio.h>
#include <stdlib.h>

typedef struct list_t
{
    uint64_t count;
    struct list_node_t *head;
    struct list_node_t *tail;
    void (*free_func)(void *);
} list_t;

typedef struct list_node_t
{
    struct list_node_t *prev;
    struct list_node_t *next;
    void *data;
} list_node_t;

list_t *
list_new(void (*free_func)(void *));

void *
list_find(list_t *list, bool (*predicate)(void *));

void
list_destroy(list_t *list);

void
list_add(list_t *list, void *data);

bool
list_pop(list_t *list, void **data);

void
list_remove(list_t *list, list_node_t *node);

void
list_foreach(list_t *list, void (*func)(uint64_t, void *));

uint64_t
list_size(list_t *list);

/* vim: set et sw=4 sts=4 tw=80: */
