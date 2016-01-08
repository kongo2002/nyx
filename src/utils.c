/* Copyright 2014-2016 Gregor Uhlenheuer
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

#define _GNU_SOURCE

#include "def.h"
#include "list.h"
#include "log.h"
#include "utils.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

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

#define ONE_M 1024UL
#define ONE_G (ONE_M * ONE_M)
#define ONE_T (ONE_G * ONE_G)

char
get_size_unit(unsigned long long kbytes, unsigned long *out_bytes)
{
    if (kbytes > 10UL * ONE_T)
    {
        *out_bytes = kbytes / ONE_T;
        return 'T';
    }

    if (kbytes > 100UL * ONE_G)
    {
        *out_bytes = kbytes / ONE_G;
        return 'G';
    }

    if (kbytes > 100UL * ONE_M)
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
    unsigned long long size = 0;

    if ((matched = sscanf(input, "%llu %c", &size, &unit)) >= 1)
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

void
wait_interval(unsigned int seconds)
{
    struct timeval tv;

    tv.tv_usec = 0;
    tv.tv_sec = seconds;

    select(1, NULL, NULL, NULL, &tv);
}

void
wait_interval_fd(int fd, unsigned int seconds)
{
    if (fd > 0)
    {
        struct timeval tv;

        tv.tv_usec = 0;
        tv.tv_sec = seconds;

        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);

        select(fd+1, &set, NULL, NULL, &tv);
    }
    else
    {
        /* if there is no valid file descriptor
         * there is no way to properly select
         * this will happen on OSX as there is
         * no event fd support */
        wait_interval(seconds);
    }
}

const char **
strings_to_null_terminated(list_t *list)
{
    unsigned long size = list_size(list);
    const char **output = NULL;

    if (size > 0)
    {
        unsigned long i = 0;
        output = xcalloc(size + 1, sizeof(char *));

        list_node_t *node = list->head;
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
split_string(const char *str, const char *chars)
{
    char *string, *token, *to_free;
    const char **output;
    list_t *tokens;

    if (str == NULL || *str == '\0')
        return NULL;

    string = strdup(str);
    to_free = string;
    tokens = list_new(NULL);

    while ((token = strsep(&string, chars)) != NULL)
    {
        if (!empty_or_whitespace(token))
            list_add(tokens, strdup(token));
    }

    output = strings_to_null_terminated(tokens);
    free(to_free);

    return output;
}

uint32_t
count_args(const char **args)
{
    uint32_t count = 0;
    const char **arg = args;

    while (*arg)
    {
        count++;
        arg++;
    }

    return count;
}

const char **
split_string_whitespace(const char *str)
{
    return split_string(str, " \t");
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
