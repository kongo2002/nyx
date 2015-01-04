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
#include "utils.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int
empty_or_whitespace(const char *str)
{
    char c;

    if (str == NULL)
        return 1;

    while ((c = *str) != '\0')
    {
        if (!isspace(c))
            return 0;
        str++;
    }

    return 1;
}

const char **
split_string(const char *str)
{
    unsigned long i = 0, size = 0;
    static const char *whitespace = " \t";
    char *string, *token, *to_free;
    const char **output;
    list_node_t *node;
    list_t *tokens;

    if (str == NULL || *str == '\0')
        return NULL;

    string = strdup(str);
    to_free = string;
    tokens = list_new(NULL);

    while ((token = strsep(&string, whitespace)) != NULL)
    {
        if (!empty_or_whitespace(token))
            list_add(tokens, strdup(token));
    }

    size = list_size(tokens);

    if (size < 1)
        return NULL;

    output = xcalloc(size + 1, sizeof(char *));

    node = tokens->head;
    while (node)
    {
        output[i++] = node->data;
        node = node->next;
    }

    list_destroy(tokens);
    free(to_free);

    return output;
}

void
strings_free(char **strings)
{
    if (strings == NULL)
        return;

    char **string = strings;

    while (*string)
    {
        free(*string);
        string++;
    }

    free(strings);
}

/* vim: set et sw=4 sts=4 tw=80: */
