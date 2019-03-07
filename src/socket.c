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

#include "log.h"
#include "socket.h"
#include "def.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define NYX_PORT_CHECK_CONN_TIMEOUT_SECS 3

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

static endpoint_t *
endpoint_new(uint16_t port, const char *host)
{
    endpoint_t *endpoint = xcalloc1(sizeof(endpoint_t));

    endpoint->port = port;
    endpoint->host = host != NULL ? strdup(host) : NULL;

    return endpoint;
}

void
endpoint_free(endpoint_t *endpoint)
{
    if (endpoint == NULL)
        return;

    if (endpoint->host)
        free((void *)endpoint->host);

    free(endpoint);
}

endpoint_t *
parse_endpoint(const char *input)
{
    uint16_t port = 0;
    endpoint_t *endpoint = NULL;

    if (input == NULL || *input == '\0')
        return NULL;

    char *copy = strdup(input);
    char *to_free = copy;
    char *host = strsep(&copy, ":");

    /* there is no colon in the input
     * this has to be a port number */
    if (copy == NULL)
    {
        port = atoi(input);

        if (port > 0)
            endpoint = endpoint_new(port, NULL);
    }
    else
    {
        char *port_str = strsep(&copy, ":");
        if (port_str != NULL)
        {
            port = atoi(port_str);

            if (port > 0)
                endpoint = endpoint_new(port, host);
        }
    }


    free(to_free);
    return endpoint;
}

ssize_t
send_status_safe(int32_t sock, int32_t status)
{
    char buffer[] = { 0, '0' + status, 0 };
    return send_safe(sock, buffer, 3);
}

/* OS agnostic send() method wrapper */
ssize_t
send_safe(int32_t sock, const void *buffer, size_t length)
{
    return send(sock, buffer, length,
#ifdef OSX
            0
#else
            MSG_NOSIGNAL
#endif
            );
}

bool
unblock_socket(int32_t sock)
{
    int32_t flags = fcntl(sock, F_GETFL, 0);

    if (flags == -1)
    {
        log_perror("nyx: fcntl");
        return false;
    }

    /* add non-blocking flag */
    flags |= O_NONBLOCK;

    int32_t err = fcntl(sock, F_SETFL, flags);

    if (err == -1)
    {
        log_perror("nyx: fcntl");
        return false;
    }

    return true;
}

#define REQUEST_TEMPLATE "%s /%s HTTP/1.0\r\nHost: localhost\r\nUser-Agent: nyx\r\n\r\n"

static char *
build_request(const char *url, http_method_e method)
{
    const char *mtd = http_method_to_string(method);
    size_t url_len = url ? strlen(url) : 0;
    size_t length = LEN(REQUEST_TEMPLATE) + url_len + strlen(mtd);

    char *request = xcalloc(length, sizeof(char));

    const char *path = url ? url : "";

    /* remove leading slash if necessary */
    if (*path == '/')
        path = path + 1;

    snprintf(request, length, REQUEST_TEMPLATE, mtd, path);

    return request;
}

#undef REQUEST_TEMPLATE

bool
check_http(const char *url, uint16_t port, http_method_e method)
{
    bool success = false;
    ssize_t total = 0, res = 0;
    char *request = NULL;
    struct sockaddr_in srv;

    int32_t sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd < 1)
    {
        log_perror("nyx: socket");
        return false;
    }

    /* set timeouts */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000; /* micro seconds */

    /* set receive timeout */
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)))
    {
        log_perror("nyx: setsockopt");
        goto end;
    }

    /* set send timeout */
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)))
    {
        log_perror("nyx: setsockopt");
        goto end;
    }

    memset(&srv, 0, sizeof(struct sockaddr_in));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port ? port : 80);

    if (!inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr))
        goto end;

    if (connect(sockfd, (struct sockaddr *) &srv, sizeof(struct sockaddr_in)) != 0)
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
            success = true;
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

bool
check_port(const char *host, uint16_t port)
{
    bool success = false;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int32_t err = getaddrinfo(host, NULL, &hints, &result);
    if (err != 0)
    {
        log_warn("nyx: getaddrinfo: %s", gai_strerror(err));
        return false;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        int32_t sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
        {
            log_perror("nyx: socket");
            continue;
        }

        /* overwrite port */
        struct sockaddr_in *sin = (struct sockaddr_in *)rp->ai_addr;
        sin->sin_port = htons(port);

        /* set socket into non blocking mode */
        if (unblock_socket(sock))
        {
            fd_set set;
            struct timeval tv;

            tv.tv_usec = 0;
            tv.tv_sec = NYX_PORT_CHECK_CONN_TIMEOUT_SECS;

            /* the connect will immediately return */
            connect(sock, rp->ai_addr, rp->ai_addrlen);

            FD_ZERO(&set);
            FD_SET(sock, &set);

            /* select will listen on the socket */
            if (select(sock+1, NULL, &set, NULL, &tv) == 1)
            {
                int32_t so_error;
                socklen_t len = sizeof(so_error);

                /* determine if connection succeeded */
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0)
                {
                    close(sock);
                    success = true;
                    break;
                }
            }
        }

        close(sock);
    }

    freeaddrinfo(result);

    return success;
}

bool
check_local_port(uint16_t port)
{
    bool success = false;
    struct sockaddr_in srv;

    int32_t sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        log_perror("nyx: socket");
        return false;
    }

    memset(&srv, 0, sizeof(struct sockaddr_in));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);

    if (!inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr))
        goto end;

    if (connect(sockfd, (struct sockaddr *) &srv, sizeof(srv)) == 0)
        success = true;
    else
        log_perror("nyx: connect");

end:
    close(sockfd);
    return success;
}

#ifdef OSX
bool
add_epoll_socket(int32_t sock, struct kevent *event, int32_t epoll, int32_t remote)
{
    memset(event, 0, sizeof(struct kevent));

    epoll_extra_data_t *data = epoll_extra_data_new(sock, remote);

    /* add read mask */
    EV_SET(event, sock, EVFILT_READ, EV_ADD, 0, 0, data);

    int32_t error = kevent(epoll, event, 1, NULL, 0, NULL);

    if (error == -1)
        log_perror("nyx: kevent");

    return !error;
}
#else
bool
add_epoll_socket(int32_t sock, struct epoll_event *event, int32_t epoll, int32_t remote)
{
    memset(event, 0, sizeof(struct epoll_event));

    epoll_extra_data_t *data = epoll_extra_data_new(sock, remote);

    event->data.ptr = data;
    event->events = EPOLLIN | EPOLLRDHUP;

    int32_t error = epoll_ctl(epoll, EPOLL_CTL_ADD, sock, event);

    if (error == -1)
        log_perror("nyx: epoll_ctl");

    return !error;
}
#endif

epoll_extra_data_t *
epoll_extra_data_new(int32_t fd, int32_t remote)
{
    epoll_extra_data_t *extra = xcalloc1(sizeof(epoll_extra_data_t));

    extra->fd = fd;
    extra->remote_socket = remote;

    return extra;
}

/* vim: set et sw=4 sts=4 tw=80: */
