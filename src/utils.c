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

#define _GNU_SOURCE

#include "def.h"
#include "list.h"
#include "log.h"
#include "strbuf.h"
#include "utils.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <wordexp.h>

bool
empty_or_whitespace(const char *str)
{
    char c;

    if (str == NULL)
        return true;

    while ((c = *str) != '\0')
    {
        if (!isspace(c))
            return false;
        str++;
    }

    return true;
}

#define ONE_M 1024UL
#define ONE_G (ONE_M * ONE_M)
#define ONE_T (ONE_G * ONE_G)

char
get_size_unit(uint64_t kbytes, uint64_t *out_bytes)
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

uint32_t
parse_time_unit(const char *input)
{
    char unit;
    int32_t matched = 0;
    uint32_t seconds = 0;

    if ((matched = sscanf(input, "%u %c", &seconds, &unit)) >= 1)
    {
        /* no unit specified -> default to seconds */
        if (matched == 1)
            return seconds;

        switch (unit)
        {
            case 's':
            case 'S':
                return seconds;
            case 'm':
            case 'M':
                return seconds * 60;
            case 'h':
            case 'H':
                return seconds * 3600;
            default:
                log_error("Invalid time unit specified: %c", unit);
                return 0;
        }
    }
    else if (matched == -1)
    {
        log_perror("nyx: sscanf");
    }

    return 0;
}

uint64_t
parse_size_unit(const char *input)
{
    char unit;
    int32_t matched = 0;
    uint64_t size = 0;

    if ((matched = sscanf(input, "%" PRIu64 " %c", &size, &unit)) >= 1)
    {
        /* no unit specified -> default to kilobytes */
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
wait_interval(uint32_t seconds)
{
    struct timeval tv;

    tv.tv_usec = 0;
    tv.tv_sec = seconds;

    select(1, NULL, NULL, NULL, &tv);
}

void
wait_interval_fd(int32_t fd, uint32_t seconds)
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
    uint64_t size = list_size(list);
    const char **output = NULL;

    if (size > 0)
    {
        uint64_t i = 0;
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

const char **
parse_command_string(const char *str)
{
    if (str == NULL || *str == '\0')
        return NULL;

    char *string = strdup(str);
    size_t length = strlen(string);
    uint32_t idx = 0;
    char *chr = string, *part = string;
    list_t *parts = list_new(NULL);
    char str_delim = '\0';
    bool found_special = false;

    while (*chr)
    {
        idx++;

        /* whitespace */
        if (*chr == ' ' || *chr == '\t')
        {
            /* start of the string */
            if (part == chr)
            {
                if (str_delim == '\0')
                    part++;
            }
            /* end of the string and *not* in-string */
            else if (str_delim == '\0')
            {
                *chr = '\0';
                list_add(parts, strdup(part));
                part = chr + 1;
            }

            chr++;
            continue;
        }

        /* check escape */
        if (*chr == '\\')
        {
            found_special = true;

            /* shift the whole string one byte to the left */
            memmove(chr, chr+1, length - idx + 1);
            chr++;
            continue;
        }

        /* check string delimiters */
        if (*chr == '"' || *chr == '\'')
        {
            found_special = true;

            if (str_delim == *chr)
            {
                *chr = '\0';
                str_delim = '\0';
                list_add(parts, strdup(part));
                chr++;
                part = chr;
                continue;
            }
            /* not in string already */
            else if (str_delim == '\0')
            {
                str_delim = *chr;

                /* start of the 'part' */
                if (chr == part)
                    part++;
                else
                    memmove(chr, chr+1, length - idx + 1);
            }
        }

        chr++;
    }

    if (!empty_or_whitespace(part))
        list_add(parts, strdup(part));

    free(string);

    if (found_special)
    {
        log_warn("nyx tries hard to parse your command - however consider using"
                 " YAML's list syntax for more complicated command strings");
    }

    return strings_to_null_terminated(parts);
}

static char *
join_strings(char **parts)
{
    char **part = parts;

    if (!part)
        return NULL;

    strbuf_t *buffer = strbuf_new();

    while (*part)
    {
        /* prepend space if necessary */
        if (part != parts)
            strbuf_append(buffer, " %s", *part);
        else
            strbuf_append(buffer, "%s", *part);

        part++;
    }

    char *result = buffer->length > 0
        ? strdup(buffer->buf)
        : NULL;

    strbuf_free(buffer);
    return result;
}

bool
substitute_env_string(const char *input, char **output)
{
    bool success = false;
    wordexp_t subst;

    *output = NULL;

    if (input == NULL || *input == '\0')
        return false;

    switch (wordexp(input, &subst, WRDE_NOCMD | WRDE_UNDEF))
    {
        // success
        case 0:
            if (subst.we_wordc > 0)
                *output = join_strings(subst.we_wordv);
            wordfree(&subst);
            success = true;
            break;

        case WRDE_BADCHAR:
            log_warn("environment contains illegal characters");
            break;
        case WRDE_BADVAL:
            log_warn("environment contains an undefined variable");
            break;
        case WRDE_CMDSUB:
            log_warn("commands in environments are not supported");
            break;
        case WRDE_NOSPACE:
            log_warn("out of memory");
            wordfree(&subst);
            break;
        case WRDE_SYNTAX:
            log_warn("invalid environment given");
            break;

        default:
            break;
    }

    return success;
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
