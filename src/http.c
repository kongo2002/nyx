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

#include "http.h"
#include "nyx.h"
#include "log.h"
#include "socket.h"

#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>

static volatile int need_exit = 0;

static int
http_init(const char *port)
{
    int sock_fd = 0, err = 0;

    /* get host address */
    struct addrinfo hints, *res = NULL, *addr = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    /* AI_PASSIVE and NULL as 'node' will result in the
     * wildcard interface */
    err = getaddrinfo(NULL, port, &hints, &res);

    if (err != 0)
    {
        log_perror("nyx: getaddrinfo");
        return 0;
    }

    /* bind to the first working address */
    for (addr = res; addr != NULL; addr = addr->ai_next)
    {
        sock_fd = socket(addr->ai_family, addr->ai_socktype, 0);

        if (sock_fd == -1)
            continue;

        if (bind(sock_fd, addr->ai_addr, addr->ai_addrlen) == 0)
            break;

        /* bind did not work out */
        close(sock_fd);
    }

    freeaddrinfo(res);

    /* connect and bind did not succeed */
    if (addr == NULL)
        return 0;

    /* start listening */
    if (listen(sock_fd, 64) != 0)
    {
        log_perror("nyx: listen");
        close(sock_fd);
        return 0;
    }

    return sock_fd;
}

static void
handle_requests(int sock_fd)
{
}

void *
http_start(void *obj)
{
    nyx_t *nyx = obj;
    int sock_fd = 0;
    char port[8] = {0};

    sprintf(port, "%u", nyx->options.http_port);

    while (!need_exit)
    {
        if (sock_fd)
            close(sock_fd);

        if ((sock_fd = http_init(port)) != 0)
        {
            log_debug("Start listening on port %u", nyx->options.http_port);

            handle_requests(sock_fd);
            break;
        }
    }

    if (sock_fd)
        close(sock_fd);

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
