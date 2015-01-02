#ifndef __NYX_PROCESS_H__
#define __NYX_PROCESS_H__

#include "nyx.h"

pid_t
determine_pid(const char *name, nyx_t *nyx);

int
write_pid(pid_t pid, const char *name, nyx_t *nyx);

int
check_process_running(pid_t pid);

int
clear_pid(const char *name, nyx_t *nyx);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
