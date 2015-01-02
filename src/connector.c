#include "connector.h"
#include "def.h"
#include "log.h"
#include "nyx.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static volatile int need_exit = 0;

void
connector_close()
{
    need_exit = 1;
}

void *
connector_start(UNUSED void *nyx)
{
    static int max_conn = 4;

    char buffer[512] = {0};
    ssize_t received = 0;
    int sock = 0, error = 0, client = 0, finished = 0;

    struct sockaddr_un addr;
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/god.sock", sizeof(addr.sun_path)-1);

    log_debug("Starting connector");

    /* create a UNIX domain, connection based socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock == -1)
    {
        log_perror("nyx: socket");
        return NULL;
    }

    /* remove any existing god sockets */
    unlink("/tmp/god.sock");

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

            /* just for now... */
            fwrite(buffer, 1, received, stdout);
        }

        close(client);
    }

    close(sock);

    log_debug("Connector: terminated");

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
