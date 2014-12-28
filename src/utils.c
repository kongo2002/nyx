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

    output = calloc(size + 1, sizeof(char *));

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
