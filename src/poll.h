#ifndef __NYX_POLL_H__
#define __NYX_POLL_H__

#include "nyx.h"

typedef int (*poll_handler_t)(int pid, int running, nyx_t *nyx);

int
poll_loop(nyx_t *nyx, poll_handler_t handler);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
