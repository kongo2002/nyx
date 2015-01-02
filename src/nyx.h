#ifndef __NYX_H__
#define __NYX_H__

#include "hash.h"
#include "list.h"

#include <sys/types.h>

typedef struct
{
    int quiet;
    int no_color;
    int syslog;
    const char *config_file;
    int def_start_timeout;
    int def_grace;
} nyx_options_t;

typedef struct
{
    pid_t pid;
    int is_init;
    const char *pid_dir;
    pthread_t *connector_thread;
    nyx_options_t options;
    hash_t *watches;
    list_t *states;
} nyx_t;

void
print_usage(FILE *out);

void
print_help(void) __attribute__((noreturn));

nyx_t *
nyx_initialize(int argc, char **args);

int
nyx_watches_init(nyx_t *nyx);

void
setup_signals(nyx_t *nyx, void (*terminate_handler)(int));

void
nyx_destroy(nyx_t *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
