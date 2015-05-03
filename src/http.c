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

#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>

#define NYX_MAX_REQUEST_LEN 1024

static int
not_found(int fd)
{
    const char response[] = "HTTP/1.0 404 Not Found\r\n"
        "Server: nyx\r\n"
        "Content-Length: 10\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "not found";

    return send(fd, response, LEN(response), MSG_NOSIGNAL) > 0;
}

static int
bad_request(int fd)
{
    const char response[] = "HTTP/1.0 400 Bad Request\r\n"
        "Server: nyx\r\n"
        "Content-Length: 12\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "bad request";

    return send(fd, response, LEN(response), MSG_NOSIGNAL) > 0;
}

static int
parse_header(epoll_extra_data_t *extra)
{
    char *buffer = extra->buffer;
    char *hd_http, *hd_method, *hd_uri, *save_ptr;

    /* minimum header length */
    if (extra->pos < 4)
        return 0;

    /* parse method */
    hd_method = strtok_r(buffer, " ", &save_ptr);
    if (hd_method == NULL)
        return 0;

    /* currently GET is supported only */
    if (strncmp(hd_method, "GET", 3) != 0)
        return 0;

    /* parse uri */
    hd_uri = strtok_r(NULL, " ", &save_ptr);
    if (hd_uri == NULL || *hd_uri != '/')
        return 0;

    /* parse http version */
    hd_http = strtok_r(NULL, " ", &save_ptr);
    if (hd_http == NULL)
        return 0;

    if (strncmp(hd_http, "HTTP/1.", 7) != 0)
        return 0;

    /* return length of the method part */
    return hd_uri - buffer;
}

static int
parse_request(epoll_extra_data_t *extra)
{
    unsigned method_len = parse_header(extra);

    if (!method_len)
        return 0;

    /* skip method portion of request line */
    const char *uri = extra->buffer + method_len;

    log_debug("Received HTTP request to '%s'", uri);

    return 1;
}

int
http_handle_request(struct epoll_event *event, nyx_t *nyx)
{
    int success = 0;
    ssize_t received = 0;

    epoll_extra_data_t *extra = event->data.ptr;

    /* start of new request? */
    if (extra->length == 0)
    {
        log_debug("Incoming HTTP request");

        /* initialize message buffer */
        extra->buffer = xcalloc(NYX_MAX_REQUEST_LEN + 1, sizeof(char));
        extra->length = NYX_MAX_REQUEST_LEN;
    }

    received = recv(extra->fd, extra->buffer + extra->pos, extra->length - extra->pos, 0);

    if (received < 1)
    {
        if (received < 0)
        {
            if (errno == EAGAIN)
                return 1;
            else
            {
                log_perror("nyx: recv");
                goto close;
            }
        }
    }

    extra->pos += received;

    if (!parse_request(extra))
        bad_request(extra->fd);
    else
        not_found(extra->fd);

    success = 1;

close:
    extra->pos = 0;
    extra->length = 0;

    if (extra->buffer)
    {
        free(extra->buffer);
        extra->buffer = NULL;
    }

    close(extra->fd);

    free(extra);
    event->data.ptr = NULL;

    return success;
}


int
http_init(unsigned port)
{
    int sock_fd = 0, err = 0;
    char port_buffer[8] = {0};

    sprintf(port_buffer, "%u", port);

    /* get host address */
    struct addrinfo hints, *res = NULL, *addr = NULL;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    /* AI_PASSIVE and NULL as 'node' will result in the
     * wildcard interface */
    err = getaddrinfo(NULL, port_buffer, &hints, &res);

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

/* vim: set et sw=4 sts=4 tw=80: */
