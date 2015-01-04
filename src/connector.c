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

#include "connector.h"
#include "def.h"
#include "log.h"
#include "nyx.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>

#define NYX_SOCKET_ADDR "/tmp/nyx.sock"

static volatile int need_exit = 0;

#define CMD(t, n, h) \
    { .type = t, .name = n, .handler = h, .cmd_length = LEN(n) }

static command_t commands[] =
{
    CMD(CMD_PING, "ping", NULL),
    CMD(CMD_VERSION, "version", NULL),
    CMD(CMD_TERMINATE, "terminate", NULL),
    CMD(CMD_START, "start", NULL),
    CMD(CMD_STOP, "stop", NULL),
};

#undef CMD

command_t *
parse_command(const char *input)
{
    size_t i = 0;
    size_t size = LEN(commands);
    command_t *command = commands;

    while (i < size)
    {
        if (!strncmp(command->name, input, command->cmd_length))
            return command;

        command++; i++;
    }

    return NULL;
}

const char *
connector_call(command_t *cmd)
{
    int sock = 0, err = 0;
    char buffer[512] = {0};
    const char *result = NULL;
    struct sockaddr_un addr;

    /* create a UNIX domain, connection based socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock == -1)
    {
        log_perror("nyx: socket");
        return NULL;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, NYX_SOCKET_ADDR, sizeof(addr.sun_path)-1);

    err = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

    if (err == -1)
    {
        log_perror("nyx: connect");
        return NULL;
    }

    if (send(sock, cmd->name, cmd->cmd_length, 0) == -1)
    {
        log_perror("nyx: send");
    }
    else
    {
        if ((err = recv(sock, buffer, 512, 0)) > 0)
        {
            result = strndup(buffer, 512);
        }
        else if (err < 0)
        {
            log_perror("nyx: recv");
        }
    }

    close(sock);
    return result;
}

static int
send_callback(sender_callback_t *callback, const char *output)
{
    if (callback == NULL || output == NULL || *output == '\0')
        return 0;

    ssize_t sent = 0;
    sent = send(callback->client, output, strlen(output), 0);

    if (sent == -1)
        log_perror("nyx: send");

    return sent;
}

static int
handle_command(command_t *cmd, int client, const char *input, nyx_t *nyx)
{
    if (cmd->handler == NULL)
        return 0;

    int retval = 0;
    sender_callback_t *callback = xcalloc(1, sizeof(sender_callback_t));

    callback->command = cmd->type;
    callback->client = client;
    callback->sender = send_callback;

    retval = cmd->handler(callback, input, nyx);

    free(callback);
    return retval;
}

void
connector_close()
{
    need_exit = 1;
}

void *
connector_start(void *state)
{
    static int max_conn = 4;

    nyx_t *nyx = state;
    command_t *cmd = NULL;
    char buffer[512] = {0};
    ssize_t received = 0, sent = 0;
    int sock = 0, error = 0, client = 0, finished = 0;

    struct sockaddr_un addr;
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, NYX_SOCKET_ADDR, sizeof(addr.sun_path)-1);

    log_debug("Starting connector");

    /* create a UNIX domain, connection based socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock == -1)
    {
        log_perror("nyx: socket");
        return NULL;
    }

    /* remove any existing nyx sockets */
    unlink(NYX_SOCKET_ADDR);

    error = bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

    if (error)
    {
        log_perror("nyx: bind");
        return NULL;
    }

    error = listen(sock, max_conn);

    if (error)
    {
        log_perror("nyx: listen");
        return NULL;
    }

    while (!need_exit)
    {
        log_debug("Connector: waiting for connections");

        client = accept(sock, (struct sockaddr *)&client_addr, &client_len);

        if (client == -1)
        {
            if (errno == EINTR)
            {
                log_debug("Connector: caught interrupt");
                need_exit = 1;
            }

            log_perror("nyx: accept");
            continue;
        }

        finished = 0;

        while (!finished)
        {
            memset(buffer, 0, 512);
            received = recv(client, buffer, 512, 0);

            if (received < 1)
            {
                if (received < 0)
                {
                    if (errno == EINTR)
                    {
                        log_debug("Connector: caught interrupt");
                        need_exit = 1;
                    }

                    log_perror("nyx: recv");
                }
                break;
            }

            if ((cmd = parse_command(buffer)) != NULL)
            {
                char *output = NULL;

                log_debug("Handling command '%s' (%d)",
                        cmd->name, cmd->type);

                if (!handle_command(cmd, client, buffer, nyx))
                {
                    log_warn("Failed to process command '%s' (%d)",
                            cmd->name, cmd->type);
                }
                else
                {
                    sent = send(client, output, strlen(output), 0);

                    if (sent == -1)
                        log_perror("nyx: send");
                }
            }
        }

        close(client);
    }

    close(sock);
    unlink(NYX_SOCKET_ADDR);

    log_debug("Connector: terminated");

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
