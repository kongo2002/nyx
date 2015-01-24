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

#define ONE_M 1024L
#define ONE_G (ONE_M * ONE_M)
#define ONE_T (ONE_G * ONE_G)

char
get_size_unit(unsigned long kbytes, unsigned long *out_bytes)
{
    if (kbytes > 10 * ONE_T)
    {
        *out_bytes = kbytes / ONE_T;
        return 'T';
    }

    if (kbytes > 100 * ONE_G)
    {
        *out_bytes = kbytes / ONE_G;
        return 'G';
    }

    if (kbytes > 100 * ONE_M)
    {
        *out_bytes = kbytes / ONE_M;
        return 'M';
    }

    *out_bytes = kbytes;
    return 'K';
}

unsigned long
parse_size_unit(const char *input)
{
    char unit;
    int matched = 0;
    unsigned long size = 0;

    if ((matched = sscanf(input, "%lu %c", &size, &unit)) >= 1)
    {
        /* no unit specified
         * -> default to kilobytes */
        if (matched == 1)
            return size;

        switch (unit)
        {
            case 'k':
            case 'K':
                return size;
            case 'm':
            case 'M':
                return size * ONE_M;
            case 'g':
            case 'G':
                return size * ONE_G;
            case 't':
            case 'T':
                return size * ONE_T;
            default:
                log_error("Invalid unit specified: '%c'", unit);
                return 0;
        }
    }
    else if (matched == -1)
    {
        log_perror("nyx: sscanf");
    }

    return 0;
}

const char **
strings_to_null_terminated(list_t *list)
{
    unsigned long i = 0, size = list_size(list);
    const char **output = NULL;
    list_node_t *node = NULL;

    if (size > 0)
    {
        output = xcalloc(size + 1, sizeof(char *));

        node = list->head;
        while (node)
        {
            output[i++] = node->data;
            node = node->next;
        }
    }

    list_destroy(list);
    return output;
}

const char **
split_string(const char *str)
{
    static const char *whitespace = " \t";
    char *string, *token, *to_free;
    const char **output;
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

    output = strings_to_null_terminated(tokens);
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
