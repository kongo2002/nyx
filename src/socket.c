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

#include "log.h"
#include "socket.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int
unblock_socket(int socket)
{
    int flags = 0, err = 0;

    flags = fcntl(socket, F_GETFL, 0);

    if (flags == -1)
    {
        log_perror("nyx: fcntl");
        return 0;
    }

    /* add non-blocking flag */
    flags |= O_NONBLOCK;

    err = fcntl(socket, F_SETFL, flags);

    if (err == -1)
    {
        log_perror("nyx: fcntl");
        return 0;
    }

    return 1;
}

int
check_port(unsigned port)
{
    int success = 0;
    struct sockaddr_in srv;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        log_perror("nyx: socket");
        return 0;
    }

    memset(&srv, 0, sizeof(srv));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);

    if (!inet_aton("127.0.0.1", &srv.sin_addr))
        goto end;

    if (connect(sockfd, &srv, sizeof(srv)) != 0)
        log_perror("nyx: connect");
    else
        success = 1;

end:
    close(sockfd);
    return success;
}

int
add_epoll_socket(int socket, struct epoll_event *event, int epoll)
{
    int error = 0;

    memset(event, 0, sizeof(struct epoll_event));

    event->events = EPOLLIN;
    event->data.fd = socket;

    error = epoll_ctl(epoll, EPOLL_CTL_ADD, socket, event);

    if (error == -1)
        log_perror("nyx: epoll_ctl");

    return !error;
}

/* vim: set et sw=4 sts=4 tw=80: */
