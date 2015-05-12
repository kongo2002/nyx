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

#define _GNU_SOURCE

#include "connector.h"
#include "command.h"
#include "def.h"
#include "http.h"
#include "log.h"
#include "nyx.h"
#include "socket.h"
#include "state.h"
#include "utils.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define NYX_SOCKET_ADDR "/tmp/nyx.sock"

#define NYX_MAX_MSG_LEN 128

static volatile int need_exit = 0;

static int
send_format(sender_callback_t *cb, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static int
send_format_msg(sender_callback_t *cb, const char *format, va_list values)
{
    char *msg;
    int sent = 0;
    int length = vasprintf(&msg, format, values);

    if (length > 0)
    {
        int res = 0;

        /* send message itself */
        if ((res = send(cb->client, msg, length, MSG_NOSIGNAL)) < 0)
            log_perror("nyx: send");

        if (res > 0)
        {
            char newline[1] = {'\n'};

            sent += res;

            /* send newline */
            if ((res = send(cb->client, newline, 1, MSG_NOSIGNAL)) < 0)
                log_perror("nyx: send");
            else
                sent += res;
        }

        free(msg);
    }

    return sent;
}

static int
send_format(sender_callback_t *cb, const char *format, ...)
{
    int sent;
    va_list vas;
    va_start(vas, format);

    sent = send_format_msg(cb, format, vas);

    va_end(vas);

    return sent;
}


static size_t
get_message_length(const char **strings, int count)
{
    int i = count;
    size_t length = 0;
    const char **string = strings;

    while (i-- > 0)
    {
        if (*string)
            length += strlen(*string);

        string++;
    }

    return length + count - 1;
}

static const char *
get_message(const char **commands, int count)
{
    size_t length = get_message_length(commands, count);

    /* buffer size: header (2 chars) + message length + NULL */
    char *message = xcalloc(length + 3, sizeof(char));
    const char **cmd = commands;
    char *start = message + 2;

    /* write header = message length */
    sprintf(message, "%2lu", length);

    /* write commands itself */
    while (count-- > 0)
    {
        int len = sprintf(start, "%s", *cmd);

        if (count > 0)
        {
            start += len;
            *start = ' ';
            start++;
        }

        cmd++;
    }

    return message;
}

static ssize_t
send_command(int socket, const char **commands, int quiet)
{
    ssize_t sent = 0;
    unsigned int num_args = count_args(commands);
    const char *message = get_message(commands, num_args);

    if (!quiet)
    {
        /* skip header */
        printf("<<< %s\n", message + 2);
    }

    sent = send(socket, message, strlen(message), MSG_NOSIGNAL);

    if (sent == -1)
        log_perror("nyx: send");

    free((void *)message);

    return sent;
}

static void
print_response(char *buffer, size_t len, int quiet)
{
    size_t idx = 0;
    char *msg = buffer, *ptr = buffer;

    while (idx++ < len)
    {
        if (*ptr == '\0' || *ptr == '\n')
        {
            *ptr = '\0';

            if (!quiet)
                printf(">>> %s\n", msg);
            else
                printf("%s\n", msg);

            if (idx < len)
                msg = ptr + 1;
        }

        if (idx < len)
            ptr++;
    }
}

int
connector_call(const char **commands, int quiet)
{
    int sock = 0, res = 0, success = 0;
    char buffer[1024] = {0};
    size_t total = 0, size = LEN(buffer);
    struct sockaddr_un addr;

    /* create a UNIX domain, connection based socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock == -1)
    {
        log_perror("nyx: socket");
        return 0;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, NYX_SOCKET_ADDR, sizeof(addr.sun_path)-1);

    res = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

    if (res == -1)
    {
        /* specialized error message for the common scenario
         * that the daemon is not running */
        if (errno == ENOENT)
            log_error("Failed to connect to nyx - the daemon is probably not running");
        else
            log_perror("nyx: connect");

        return 0;
    }

    if (send_command(sock, commands, quiet) == -1)
    {
        log_perror("nyx: send");
    }
    else
    {
        int done = 0;

        do
        {
            if ((res = recv(sock, buffer+total, size-total-1, 0)) > 0)
            {
                total += res;
            }
            else if (res == 0)
            {
                done = 1;
                success = 1;
            }
            else
            {
                log_perror("nyx: recv");
                done = 1;
            }
        } while (!done && total + 1 < size);

    }

    close(sock);

    if (success)
        print_response(buffer, total, quiet);

    return success;
}

static int
handle_command(command_t *cmd, int client, const char **input, nyx_t *nyx)
{
    if (cmd->handler == NULL)
        return 0;

    int retval = 0;
    sender_callback_t *callback = xcalloc1(sizeof(sender_callback_t));

    callback->command = cmd->type;
    callback->client = client;
    callback->sender = send_format;

    retval = cmd->handler(callback, input, nyx);

    free(callback);
    return retval;
}

static void
init_nyx_addr(struct sockaddr_un *addr)
{
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, NYX_SOCKET_ADDR, sizeof(addr->sun_path)-1);
}

static int
handle_request(struct epoll_event *event, nyx_t *nyx)
{
    int success = 0;
    ssize_t received = 0;

    epoll_extra_data_t *extra = event->data.ptr;
    int fd = extra->fd;

    /* start of new request? */
    if (extra->length == 0)
    {
        /* initialize message buffer */
        extra->buffer = xcalloc(NYX_MAX_MSG_LEN + 1, sizeof(char));

        /* read message length header */
        received = recv(fd, extra->buffer, 2, 0);

        if (received != 2)
        {
            if (received == -1)
                log_perror("nyx: recv");

            goto close;
        }

        int parsed = sscanf(extra->buffer, "%2u", &extra->length);

        if (parsed != 1 || extra->length < 1)
            goto close;

        extra->length = MIN(NYX_MAX_MSG_LEN, extra->length);
    }

    received = recv(fd, extra->buffer + extra->pos, extra->length - extra->pos, 0);

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

    if (extra->pos < extra->length)
        return 1;

    /* parse input buffer */
    command_t *cmd = NULL;
    const char **commands = split_string_whitespace(extra->buffer);

    if ((cmd = parse_command(commands)) != NULL)
    {
        log_debug("Handling command '%s' (%d)",
                cmd->name, cmd->type);

        if (!handle_command(cmd, fd, commands, nyx))
        {
            log_warn("Failed to process command '%s' (%d)",
                    cmd->name, cmd->type);
        }
    }
    else
    {
        const char error[] = "unknown command\n";
        send(fd, error, LEN(error), MSG_NOSIGNAL);
    }

    strings_free((char **)commands);
    success = 1;

close:
    extra->pos = 0;
    extra->length = 0;

    if (extra->buffer)
    {
        free(extra->buffer);
        extra->buffer = NULL;
    }

    close(fd);

    free(extra);
    event->data.ptr = NULL;

    return success;
}

static void
handle_eventfd(struct epoll_event *event, nyx_t *nyx)
{
    int err = 0;
    uint64_t value = 0;
    epoll_extra_data_t *extra = event->data.ptr;
    int fd = extra->fd;

    log_debug("Received epoll event on eventfd interface (%d)", nyx->event);

    err = read(fd, &value, sizeof(value));

    if (err == -1)
        log_perror("nyx: read");

    need_exit = 1;
}

static int
connector_run(nyx_t *nyx)
{
    int restart = 0;
    static int max_conn = 16;

    int sock = 0, error = 0, epfd = 0, http_sock = 0;

    struct epoll_event base_ev, fd_ev, http_ev, ev;
    struct epoll_event *events = NULL;

    log_debug("Starting connector");

    struct sockaddr_un addr;

    init_nyx_addr(&addr);

    /* set umask before socket creation */
    mode_t old_mask = umask(0);

    /* create a UNIX domain, connection based socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock == -1)
    {
        log_perror("nyx: socket");

        umask(old_mask);
        return 0;
    }

    /* remove any existing nyx sockets */
    unlink(NYX_SOCKET_ADDR);

    /* bind to specified socket location */
    error = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

    /* restore old umask */
    umask(old_mask);

    if (error)
    {
        log_perror("nyx: bind");
        return 0;
    }

    if (!unblock_socket(sock))
        return 0;

    /* listen on requests */
    error = listen(sock, max_conn);

    if (error)
    {
        log_perror("nyx: listen");
        goto teardown;
    }

    /* initialize epoll */
    epfd = epoll_create(max_conn);
    if (epfd == -1)
    {
        log_perror("nyx: epoll_create");
        goto teardown;
    }

    /* add new listening socket to epoll instance */
    if (!add_epoll_socket(sock, &base_ev, epfd, sock))
        goto teardown;

    /* add eventfd socket to epoll as well */
    if (nyx->event > 0)
    {
        if (!unblock_socket(nyx->event))
            goto teardown;

        if (!add_epoll_socket(nyx->event, &fd_ev, epfd, sock))
            goto teardown;
    }

    /* add http socket to epoll as well (if configured) */
    if (nyx->options.http_port)
    {
        http_sock = http_init(nyx->options.http_port);

        if (http_sock)
        {
            log_debug("Initialized HTTP connector interface at port %u",
                    nyx->options.http_port);

            if (!unblock_socket(http_sock))
                goto teardown;

            if (!add_epoll_socket(http_sock, &http_ev, epfd, http_sock))
                goto teardown;
        }
    }

    events = xcalloc(max_conn, sizeof(struct epoll_event));

    while (!need_exit && !restart)
    {
        int i = 0, n = 0;
        struct epoll_event *event = NULL;

        log_debug("Connector: waiting for connections");

        n = epoll_wait(epfd, events, max_conn, -1);

        /* epoll listening failed for some reason */
        if (n < 1)
        {
            if (errno == EINTR)
            {
                log_debug("Connector: caught interrupt");
                restart = 1;
                continue;
            }

            log_perror("nyx: accept");
            continue;
        }

        /* process all received events */
        for (i = 0, event = events; i < n; event++, i++)
        {
            epoll_extra_data_t *extra = event->data.ptr;

            /* error on the socket */
            if ((event->events & EPOLLERR) ||
                (event->events & EPOLLHUP) ||
                (event->events & EPOLLRDHUP) ||
                !(event->events & EPOLLIN))
            {
                close(extra->fd);

                if (extra->buffer)
                    free(extra->buffer);

                free(extra);
                continue;
            }

            /* check for events on listening socket
             * -> accept a new connection */
            if (extra->fd == sock || (http_sock && http_sock == extra->fd))
            {
                int client = 0;
                struct sockaddr_un caddr;
                socklen_t client_len = sizeof(struct sockaddr_un);

                client = accept(extra->fd, (struct sockaddr *)&caddr, &client_len);

                if (client == -1)
                {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        log_perror("nyx: accept");
                    continue;
                }

                if (!unblock_socket(client))
                {
                    close(client);
                    continue;
                }

                if (!add_epoll_socket(client, &ev, epfd, extra->fd))
                {
                    /* TODO: free extra data? */

                    close(client);
                    continue;
                }
            }
            else if (extra->fd == nyx->event)
            {
                handle_eventfd(event, nyx);
            }
            /* incoming data from one of the client sockets */
            else
            {
                if (http_sock && extra->remote_socket == http_sock)
                {
                    if (!http_handle_request(event, nyx))
                        restart = 1;
                }
                else
                {
                    if (!handle_request(event, nyx))
                        restart = 1;
                }
            }
        }
    }

teardown:
    close(sock);

    if (epfd > 0)
        close(epfd);

    unlink(NYX_SOCKET_ADDR);

    if (events)
    {
        free(events);
        events = NULL;
    }

    if (base_ev.data.ptr)
    {
        free(base_ev.data.ptr);
        base_ev.data.ptr = NULL;
    }

    if (nyx->event > 0 && fd_ev.data.ptr)
    {
        free(fd_ev.data.ptr);
        fd_ev.data.ptr = NULL;
    }

    if (http_sock)
    {
        close(http_sock);

        if (http_ev.data.ptr)
        {
            free(http_ev.data.ptr);
            http_ev.data.ptr = NULL;
        }
    }

    log_debug("Connector: terminated");

    return restart;
}

void *
connector_start(void *state)
{
    while (!need_exit)
    {
        if (!connector_run((nyx_t *)state))
            break;
    }

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
