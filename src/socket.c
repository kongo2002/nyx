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
#include "def.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

http_method_e
http_method_from_string(const char *str)
{
    /* default to GET */
    if (str == NULL || *str == '\0')
        return HTTP_GET;

#define CMP(x, e) if (!strncasecmp(x, str, strlen(x))) return e

    CMP("GET",     HTTP_GET);
    CMP("PUT",     HTTP_PUT);
    CMP("POST",    HTTP_POST);
    CMP("OPTIONS", HTTP_OPTIONS);
    CMP("TRACE",   HTTP_TRACE);
    CMP("DELETE",  HTTP_DELETE);
    CMP("HEAD",    HTTP_HEAD);

#undef CMP

    return HTTP_GET;
}

const char *
http_method_to_string(http_method_e method)
{
    switch (method)
    {
        case HTTP_GET:
            return "GET";
        case HTTP_DELETE:
            return "DELETE";
        case HTTP_HEAD:
            return "HEAD";
        case HTTP_OPTIONS:
            return "OPTIONS";
        case HTTP_POST:
            return "POST";
        case HTTP_PUT:
            return "PUT";
        case HTTP_TRACE:
            return "TRACE";
        default:
            return "GET";
    }
}

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

#define REQUEST_TEMPLATE "%s /%s HTTP/1.0\r\nHost: localhost\r\nUser-Agent: nyx\r\n\r\n"

static char *
build_request(const char *url, http_method_e method)
{
    const char *mtd = http_method_to_string(method);
    size_t url_len = url ? strlen(url) : 0;
    size_t length = LEN(REQUEST_TEMPLATE) + url_len + strlen(mtd);

    char *request = xcalloc(length, sizeof(char));

    snprintf(request, length, REQUEST_TEMPLATE, mtd, url ? url : "");

    return request;
}

#undef REQUEST_TEMPLATE

int
check_http(const char *url, unsigned port, http_method_e method)
{
    int success = 0;
    ssize_t total = 0, res = 0;
    char *request = NULL;
    struct sockaddr_in srv;
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd < 1)
    {
        log_perror("nyx: socket");
        return 0;
    }

    /* set timeouts */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000; /* micro seconds */

    /* set receive timeout */
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)))
    {
        log_perror("nyx: setsockopt");
        return 0;
    }

    /* set send timeout */
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)))
    {
        log_perror("nyx: setsockopt");
        return 0;
    }

    memset(&srv, 0, sizeof(struct sockaddr_in));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port ? port : 80);

    if (!inet_aton("127.0.0.1", &srv.sin_addr))
        goto end;

    if (connect(sockfd, &srv, sizeof(struct sockaddr_in)) != 0)
        goto end;

    /* start sending */
    request = build_request(url, method);
    ssize_t length = strlen(request);

    while (total < length)
    {
        res = send(sockfd, request+total, length-total, 0);

        if (res == 0)
            goto end;

        if (res < 0)
        {
            log_perror("nyx: send");
            goto end;
        }

        total += res;
    }

    /* start receiving */

    /* we want to read the first HTTP header line only:
     * HTTP/1.x xxx (12 characters) */
    char buffer[13] = {0};

    res = recv(sockfd, buffer, 12, 0);

    if (res != 12)
    {
        if (res < 0)
            log_perror("nyx: recv");
        goto end;
    }

    if (strlen(buffer) == 12)
    {
        char *code = buffer + 9;

        if (strncmp(code, "200", 3) == 0)
            success = 1;
        else
        {
            log_warn("HTTP check to '%s' failed with return code %s",
                    (url ? url : "/"), code);
        }
    }

end:
    if (request)
        free(request);
    close(sockfd);

    return success;
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

    memset(&srv, 0, sizeof(struct sockaddr_in));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);

    if (!inet_aton("127.0.0.1", &srv.sin_addr))
        goto end;

    if (connect(sockfd, &srv, sizeof(srv)) == 0)
        success = 1;
    else
        log_perror("nyx: connect");

end:
    close(sockfd);
    return success;
}

int
add_epoll_socket(int socket, struct epoll_event *event, int epoll)
{
    int error = 0;

    memset(event, 0, sizeof(struct epoll_event));

    epoll_extra_data_t *data = epoll_extra_data_new(socket);

    event->data.ptr = data;
    event->events = EPOLLIN | EPOLLRDHUP;

    error = epoll_ctl(epoll, EPOLL_CTL_ADD, socket, event);

    if (error == -1)
        log_perror("nyx: epoll_ctl");

    return !error;
}

epoll_extra_data_t *
epoll_extra_data_new(int fd)
{
    epoll_extra_data_t *extra = xcalloc1(sizeof(epoll_extra_data_t));

    extra->fd = fd;

    return extra;
}

/* vim: set et sw=4 sts=4 tw=80: */
