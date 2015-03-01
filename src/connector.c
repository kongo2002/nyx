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
#include "def.h"
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
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define NYX_SOCKET_ADDR "/tmp/nyx.sock"

static volatile int need_exit = 0;

static int
send_format(sender_callback_t *cb, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static int
send_format_msg(sender_callback_t *cb, const char *format, va_list values)
{
    char newline[1] = {'\n'};
    char *msg;

    int sent = 0, res = 0;
    int length = vasprintf(&msg, format, values);

    if (length > 0)
    {
        /* send message itself */
        if ((res = send(cb->client, msg, length, 0)) < 0)
            log_perror("nyx: send");

        if (res > 0)
        {
            sent += res;

            /* send newline */
            if ((res = send(cb->client, newline, 1, 0)) < 0)
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

static int
handle_status_change(sender_callback_t *cb, const char **input, nyx_t *nyx, state_e new_state)
{
    const char *name = input[1];
    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return 0;
    }

    /* request state change */
    set_state(state, new_state);
    cb->sender(cb, "requested %s for watch '%s'",
            state_to_human_string(new_state),
            name);

    return 1;
}

static int
handle_history(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    const char *name = input[1];
    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return 0;
    }

    if (state->history->count < 1)
        return 1;

    unsigned i = state->history->count;

    while (i-- > 0)
    {
        timestack_elem_t *elem = &state->history->elements[i];
        struct tm *time = localtime(&elem->time);

        cb->sender(cb, "%04d-%02d-%02dT%02d:%02d:%02d: %s",
            time->tm_year + 1900,
            time->tm_mon,
            time->tm_mday,
            time->tm_hour,
            time->tm_min,
            time->tm_sec,
            state_to_human_string(elem->value));
    }

    return 1;
}

static int
handle_ping(sender_callback_t *cb, UNUSED const char **input, UNUSED nyx_t *nyx)
{
    return cb->sender(cb, "pong");
}

static int
handle_version(sender_callback_t *cb, UNUSED const char **input, UNUSED nyx_t *nyx)
{
    return cb->sender(cb, NYX_VERSION);
}

static int
handle_terminate(sender_callback_t *cb, UNUSED const char **input, nyx_t *nyx)
{
    need_exit = 1;

    /* trigger the eventfd */
    signal_eventfd(4, nyx);

    /* trigger the termination handler (if specified) */
    if (nyx->terminate_handler)
        nyx->terminate_handler(0);

    return cb->sender(cb, "ok");
}

static int
handle_quit(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    list_node_t *node = nyx->states->head;

    /* first we trigger the stop signal on all states */
    while (node)
    {
        state_t *state = node->data;
        set_state(state, STATE_STOPPING);

        node = node->next;
    }

    /* after that we execute the termination handler */
    return handle_terminate(cb, input, nyx);
}

static int
handle_stop(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    return handle_status_change(cb, input, nyx, STATE_STOPPING);
}

static int
handle_restart(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    return handle_status_change(cb, input, nyx, STATE_RESTARTING);
}

static int
handle_start(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    return handle_status_change(cb, input, nyx, STATE_STARTING);
}

static int
handle_status(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    const char *name = input[1];
    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return 0;
    }

    /* print pid if running */
    if (state->state == STATE_RUNNING && state->pid)
    {
        cb->sender(cb, "%s: %s (PID %d)",
                name,
                state_to_human_string(state->state),
                state->pid);
    }
    else
        cb->sender(cb, "%s: %s", name, state_to_human_string(state->state));

    return 1;
}

#define CMD(t, n, h, a, d) \
    { .type = t, .name = n, .handler = h, .min_args = a, .cmd_length = LEN(n), \
      .description = d }

static command_t commands[] =
{
    CMD(CMD_PING,       "ping",       handle_ping,       0,
            "ping the nyx server"),
    CMD(CMD_VERSION,    "version",    handle_version,    0,
            "request the nyx server version"),
    CMD(CMD_START,      "start",      handle_start,      1,
            "start the specified watch"),
    CMD(CMD_STOP,       "stop",       handle_stop,       1,
            "stop the specified watch"),
    CMD(CMD_RESTART,    "restart",    handle_restart,    1,
            "restart the specified watch"),
    CMD(CMD_STATUS,     "status",     handle_status,     1,
            "request the watch's status"),
    CMD(CMD_HISTORY,    "history",    handle_history,    1,
            "request the last watch's status'"),
    CMD(CMD_TERMINATE,  "terminate",  handle_terminate,  0,
            "terminate the nyx server"),
    CMD(CMD_QUIT,       "quit",       handle_quit,       0,
            "stop the nyx server and all watched processes")
};

#undef CMD

static unsigned int
command_max_length(void)
{
    int idx = 0;
    unsigned int len = 0;

    while (idx < CMD_SIZE)
    {
        unsigned int cmd_len = commands[idx++].cmd_length;
        len = MAX(len, cmd_len);
    }

    return len;
}

static void
print_command(FILE *out, unsigned int pad, command_t *cmd)
{
    unsigned int i = 0;

    fprintf(out, "  %s", cmd->name);

    for (i = cmd->cmd_length; i < pad; i++)
        fputc(' ', out);

    fprintf(out, "%s\n", cmd->description);
}

void
print_commands(FILE *out)
{
    int idx = 0;
    unsigned int pad_to = command_max_length() + 2;

    while (idx < CMD_SIZE)
    {
        print_command(out, pad_to, &commands[idx++]);
    }
}

static unsigned int
count_args(const char **args)
{
    unsigned int count = 0;
    const char **arg = args;

    while (*arg)
    {
        count++;
        arg++;
    }

    return count;
}

command_t *
parse_command(const char **input)
{
    size_t i = 0;
    size_t size = LEN(commands);
    unsigned int args = 0;
    command_t *command = commands;

    /* no input commands given at all */
    if (input == NULL)
        return NULL;

    while (i < size)
    {
        if (!strncmp(command->name, *input, command->cmd_length))
        {
            /* check if necessary arguments are given */
            args = count_args(input) - 1;

            if (args < command->min_args)
            {
                log_error("Command '%s' requires a minimum of %d arguments",
                        command->name,
                        command->min_args);
                return NULL;
            }

            return command;
        }

        command++; i++;
    }

    return NULL;
}

static ssize_t
send_command(int socket, const char **commands)
{
    ssize_t sum = 0, sent = 0;
    const char **cmd = commands;

    printf("<<< %s\n", *cmd);

    while (*cmd && (sent = send(socket, *cmd, strlen(*cmd), 0)) > 0)
    {
        if (send(socket, " ", 1, 0) < 1)
            return -1;

        sum += sent + 1;
        cmd++;
    }

    if (sent < 0)
        return -1;

    return sum;
}

int
connector_call(const char **commands)
{
    int sock = 0, err = 0, success = 0, done = 0;
    char buffer[512] = {0};
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

    err = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

    if (err == -1)
    {
        log_perror("nyx: connect");
        return 0;
    }

    if (send_command(sock, commands) == -1)
    {
        log_perror("nyx: send");
    }
    else
    {
        do
        {
            memset(&buffer, 0, LEN(buffer));

            if ((err = recv(sock, buffer, LEN(buffer)-1, 0)) > 0)
            {
                printf(">>> %s\n", buffer);
            }
            else if (err == 0)
            {
                done = 1;
                success = 1;
            }
            else if (err < 0)
            {
                log_perror("nyx: recv");
                done = 1;
            }
        } while (!done);
    }

    close(sock);
    return success;
}

static int
handle_command(command_t *cmd, int client, const char **input, nyx_t *nyx)
{
    if (cmd->handler == NULL)
        return 0;

    int retval = 0;
    sender_callback_t *callback = xcalloc(1, sizeof(sender_callback_t));

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
    int success = 1;
    ssize_t received = 0;
    int fd = event->data.fd;
    char buffer[512] = {0};
    const char **commands = NULL;
    command_t *cmd = NULL;

    memset(buffer, 0, 512);
    received = recv(fd, buffer, LEN(buffer)-1, 0);

    if (received < 1)
    {
        if (received < 0)
        {
            if (errno == EINTR)
            {
                log_debug("Connector: caught interrupt");
                success = 0;
            }

            if (errno != EAGAIN)
                log_perror("nyx: recv");
        }
    }
    else
    {
        /* parse input buffer */
        commands = split_string(buffer);

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

        strings_free((char **)commands);
    }

    close(fd);

    return success;
}

static void
handle_eventfd(struct epoll_event *event, nyx_t *nyx)
{
    int err = 0;
    uint64_t value = 0;

    log_debug("Received epoll event on eventfd interface (%d)", nyx->event);

    err = read(event->data.fd, &value, sizeof(value));

    if (err == -1)
        log_perror("nyx: read");

    need_exit = 1;
}

static int
connector_run(nyx_t *nyx)
{
    int restart = 0;
    static int max_conn = 16;

    int sock = 0, error = 0, epfd = 0;
    struct epoll_event *events = NULL;
    struct epoll_event ev;

    log_debug("Starting connector");

    struct sockaddr_un addr;

    init_nyx_addr(&addr);

    /* create a UNIX domain, connection based socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock == -1)
    {
        log_perror("nyx: socket");
        return 0;
    }

    /* remove any existing nyx sockets */
    unlink(NYX_SOCKET_ADDR);

    /* bind to specified socket location */
    error = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

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
    if (!add_epoll_socket(sock, &ev, epfd))
        goto teardown;

    /* add eventfd socket to epoll as well */
    if (nyx->event > 0)
    {
        if (!unblock_socket(nyx->event))
            goto teardown;

        if (!add_epoll_socket(nyx->event, &ev, epfd))
            goto teardown;
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
            /* error on the socket */
            if ((event->events & EPOLLERR) ||
                (event->events & EPOLLHUP) ||
                !(event->events & EPOLLIN))
            {
                log_warn("epoll error on socket");
                close(event->data.fd);

                continue;
            }

            /* check for events on listening socket
             * -> accept a new connection */
            if (event->data.fd == sock)
            {
                int client = 0;
                struct sockaddr_un caddr;
                socklen_t client_len = sizeof(struct sockaddr_un);

                client = accept(sock, (struct sockaddr *)&caddr, &client_len);

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

                if (!add_epoll_socket(client, &ev, epfd))
                {
                    close(client);
                    continue;
                }
            }
            else if (event->data.fd == nyx->event)
            {
                handle_eventfd(event, nyx);
            }
            /* incoming data from one of the client sockets */
            else
            {
                if (!handle_request(event, nyx))
                    restart = 1;
            }
        }
    }

teardown:
    close(sock);

    if (epfd > 0)
        close(epfd);

    unlink(NYX_SOCKET_ADDR);

    if (events)
        free(events);

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
