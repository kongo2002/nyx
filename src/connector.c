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

int
parse_command(const char *input, connector_command_e *cmd)
{
#define MATCH(x, y) \
    if (!strncmp(x, input, (sizeof(x)-1))) \
    { \
        *cmd = y; \
        return 1; \
    }

    MATCH("ping", CMD_PING)
    MATCH("version", CMD_VERSION)
    MATCH("terminate", CMD_TERMINATE)

    return 0;
#undef MATCH
}

static int
handle_command(connector_command_e cmd, char **output)
{
    switch (cmd)
    {
        case CMD_PING:
            *output = "pong";
            return 1;
        case CMD_VERSION:
            *output = "0.0.1";
            return 1;
        case CMD_TERMINATE:
            need_exit = 1;
            *output = "1";
            return 1;
        default:
            break;
    }

    return 0;
}

void
connector_close()
{
    need_exit = 1;
}

void *
connector_start(UNUSED void *nyx)
{
    static int max_conn = 4;

    connector_command_e cmd;
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

#ifndef NDEBUG
            fwrite(buffer, 1, received, stdout);
#endif

            if (parse_command(buffer, &cmd))
            {
                char *output = NULL;

                log_debug("Command %d", cmd);

                if (!handle_command(cmd, &output))
                {
                    log_warn("Failed to process command %d", cmd);
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
