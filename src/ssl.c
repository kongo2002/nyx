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

#define _DEFAULT_SOURCE

#include "def.h"
#include "log.h"
#include "ssl.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>

void
ssl_init(void)
{
    log_debug("Initializing OpenSSL");

    SSL_load_error_strings();
    ERR_load_BIO_strings();

    /* according to manpage 'SSL_library_init' always returns 1 ... */
    SSL_library_init();
}

static int32_t
tcp_connect(uint32_t port)
{
    struct sockaddr_in srv;

    int32_t sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd == -1)
    {
        log_perror("nyx: socket");
        return 0;
    }

    memset(&srv, 0, sizeof(struct sockaddr_in));

    srv.sin_family = AF_INET;
    srv.sin_port = htons(port ? port : 443);

    if (!inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr))
        return 0;

    if (connect(sockfd, (struct sockaddr *)&srv, sizeof(srv)) == 0)
        return sockfd;
    else
        log_perror("nyx: connect");

    return 0;
}

ssl_connection_t *
ssl_connect(uint32_t port)
{
    int32_t sock = tcp_connect(port);

    if (!sock)
        return NULL;

    ssl_connection_t *conn = xcalloc1(sizeof(ssl_connection_t));

    conn->socket = sock;
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

bool
https_check(uint32_t port)
{
    bool success = false;

    /* connect to SSL endpoint */
    ssl_connection_t *conn = ssl_connect(port);

    if (conn == NULL)
        return false;

    /* obtain peer certificate */
    X509 *certificate = SSL_get_peer_certificate(conn->handle);

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

    success = true;

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
