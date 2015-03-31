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

#include "def.h"
#include "log.h"
#include "ssl.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


int
ssl_init(void)
{
    log_debug("Initializing OpenSSL");

    SSL_load_error_strings();
    ERR_load_BIO_strings();

    return SSL_library_init();
}

static int
tcp_connect(int port)
{
    struct sockaddr_in srv;

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd == -1)
    {
        log_perror("nyx: socket");
        return 0;
    }

    memset(&srv, 0, sizeof(struct sockaddr_in));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port ? port : 443);

    if (!inet_aton("127.0.0.1", &srv.sin_addr))
        return 0;

    if (connect(sockfd, (struct sockaddr *)&srv, sizeof(srv)) == 0)
        return sockfd;
    else
        log_perror("nyx: connect");

    return 0;
}

ssl_connection_t *
ssl_connect(int port)
{
    int socket = tcp_connect(port);

    if (!socket)
        return NULL;

    ssl_connection_t *conn = xcalloc1(sizeof(ssl_connection_t));

    conn->socket = socket;
    conn->context = SSL_CTX_new(SSLv23_client_method());

    if (conn->context == NULL)
    {
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    /* create a SSL struct for the connection */
    conn->handle = SSL_new(conn->context);

    if (conn->handle == NULL)
    {
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    /* connect the SSL struct to our connection */
    if (!SSL_set_fd(conn->handle, conn->socket))
    {
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    /* initiate SSL handshake */
    if (SSL_connect(conn->handle) != 1)
    {
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    return conn;

fail:
    ssl_connection_destroy(conn);

    return NULL;
}

int
https_check(int port)
{
    int success = 0;
    X509 *certificate = NULL;

    /* connect to SSL endpoint */
    ssl_connection_t *conn = ssl_connect(port);

    if (conn == NULL)
        return 0;

    /* obtain peer certificate */
    certificate = SSL_get_peer_certificate(conn->handle);

    if (certificate == NULL)
    {
        log_debug("HTTPS endpoint at port %d presented no certificate", port);
        goto end;
    }

    if (SSL_get_verify_result(conn->handle) != X509_V_OK)
    {
        log_debug("HTTPS endpoint at port %d presented invalid certificate", port);
        goto end;
    }

    success = 1;

end:
    /* decrement certificate reference count */
    if (certificate != NULL)
        X509_free(certificate);

    ssl_connection_destroy(conn);

    return success;
}

void
ssl_connection_destroy(ssl_connection_t *conn)
{
    if (conn == NULL)
        return;

    if (conn->socket)
        close(conn->socket);

    if (conn->handle)
    {
        SSL_shutdown(conn->handle);
        SSL_free(conn->handle);
    }

    if (conn->context)
        SSL_CTX_free(conn->context);

    free(conn);
}

void
ssl_free(void)
{
    ERR_free_strings();
}

/* vim: set et sw=4 sts=4 tw=80: */
