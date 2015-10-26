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

#include "command.h"
#include "http.h"
#include "log.h"
#include "nyx.h"
#include "socket.h"
#include "strbuf.h"
#include "utils.h"

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

#define NYX_MAX_REQUEST_LEN 1024

#define CRLF "\r\n"

#define NYX_RESPONSE_HEADER \
    "HTTP/1.0 200 OK" CRLF \
    "Server: nyx" CRLF \
    "Content-Type: text/plain" CRLF

static int
not_found(int fd)
{
    const char response[] = "HTTP/1.0 404 Not Found" CRLF
        "Server: nyx" CRLF
        "Content-Length: 10" CRLF
        "Content-Type: text/plain" CRLF CRLF
        "not found";

    return send_safe(fd, response, LEN(response)) > 0;
}

static int
bad_request(int fd)
{
    const char response[] = "HTTP/1.0 400 Bad Request" CRLF
        "Server: nyx" CRLF
        "Content-Length: 12" CRLF
        "Content-Type: text/plain" CRLF CRLF
        "bad request";

    return send_safe(fd, response, LEN(response)) > 0;
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

static const char *
parse_request(epoll_extra_data_t *extra)
{
    unsigned method_len = parse_header(extra);

    if (!method_len)
        return 0;

    /* skip method portion of request line */
    const char *uri = extra->buffer + method_len;

    log_debug("Received HTTP request to '%s'", uri);

    return uri;
}

static int
send_format(sender_callback_t *cb, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static int
send_format(sender_callback_t *cb, const char *format, ...)
{
    int len = 0;
    char buffer[512] = {0};
    strbuf_t *str = cb->data;

    va_list vas;
    va_start(vas, format);
    len = vsnprintf(buffer, LEN(buffer), format, vas);
    va_end(vas);

    strbuf_append(str, ">>> %s\n", buffer);

    return len;
}

static int
handle_command(command_t *cmd, const char **input, epoll_extra_data_t *extra, nyx_t *nyx)
{
    int retval = 0;
    int fd = extra->fd;

    strbuf_t *str = strbuf_new();
    strbuf_t *response = strbuf_new_size(32);
    sender_callback_t *cb = xcalloc1(sizeof(sender_callback_t));

    cb->command = cmd->type;
    cb->sender = send_format;
    cb->data = str;

    retval = cmd->handler(cb, input, nyx);

    strbuf_append(response, NYX_RESPONSE_HEADER);
    strbuf_append(response, "Content-Length: %lu" CRLF CRLF, str->length);
    strbuf_append(response, "%s", str->buf);

    send_safe(fd, response->buf, response->length);

    strbuf_free(str);
    strbuf_free(response);

    free(cb);

    return retval;
}

int
http_handle_request(NYX_EV_TYPE *event, nyx_t *nyx)
{
    int success = 0;
    ssize_t received = 0;

    epoll_extra_data_t *extra = NYX_EV_GET(event);

    /* start of new request? */
    if (extra->length == 0)
    {
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


    const char *uri = parse_request(extra);
    if (uri == NULL)
        bad_request(extra->fd);
    else
    {
        command_t *cmd = NULL;
        const char **commands = split_string(uri, "/");

        if ((cmd = parse_command(commands)) != NULL && cmd->handler != NULL)
            handle_command(cmd, commands, extra, nyx);
        else
            not_found(extra->fd);

        strings_free((char **)commands);
    }

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

    NYX_EV_GET(event) = NULL;

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
