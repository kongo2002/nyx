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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define DECLARE_STACK(type_, name_) \
    typedef struct  \
    { \
        uint32_t count; \
        uint32_t max; \
        type_ *elements; \
    } stack_##name_##_t; \
    \
    stack_##name_##_t * \
    stack_##name_##_new(uint32_t size); \
    \
    void \
    stack_##name_##_destroy(stack_##name_##_t *stack); \
    \
    void \
    stack_##name_##_add(stack_##name_##_t *stack, type_ value); \
    \
    type_ \
    stack_##name_##_newest(stack_##name_##_t *stack); \
    \
    uint32_t \
    stack_##name_##_satisfy(stack_##name_##_t *stack, bool (*predicate)(type_, void *), void *obj);

#define IMPLEMENT_STACK(type_, name_) \
    stack_##name_##_t * \
    stack_##name_##_new(uint32_t size) \
    { \
        stack_##name_##_t *stack = xcalloc1(sizeof(stack_##name_##_t)); \
        stack->max = size; \
        stack->elements = xcalloc(size, sizeof(type_)); \
        return stack; \
    } \
    \
    void \
    stack_##name_##_destroy(stack_##name_##_t *stack) \
    { \
        free(stack->elements); \
        free(stack); \
    } \
    \
    void \
    stack_##name_##_add(stack_##name_##_t *stack, type_ value) \
    { \
        uint32_t size = stack->max; \
        uint32_t count = stack->count + 1; \
        stack->count = MIN(size, count); \
        type_ *start = stack->elements; \
        type_ *to = start + 1; \
        memmove(to, start, sizeof(type_) * (size - 1)); \
        *start = value; \
    } \
    \
    type_ \
    stack_##name_##_newest(stack_##name_##_t *stack) \
    { \
        return stack->elements[0]; \
    } \
    \
    uint32_t \
    stack_##name_##_satisfy(stack_##name_##_t *stack, bool (*predicate)(type_, void *), void *obj) \
    { \
        uint32_t i = 0, count = 0; \
        while (i < stack->count) \
        { \
            if (predicate(stack->elements[i++], obj)) \
                count++; \
        } \
        return count; \
    }


/* vim: set et sw=4 sts=4 tw=80: */
