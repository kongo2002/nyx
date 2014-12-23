#include "config.h"

#include <stdio.h>

int
main(int argc, char **argv)
{
    puts("Starting nyx");

    if (argc < 2)
    {
        fputs("No config file given\n", stderr);
        return 1;
    }

    if (!parse_config(argv[1]))
        return 1;

    return 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
