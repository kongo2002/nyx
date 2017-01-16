/* Copyright 2014-2017 Gregor Uhlenheuer
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

#pragma once

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct
{
    int32_t socket;
    SSL *handle;
    SSL_CTX *context;
} ssl_connection_t;

void
ssl_init(void);

ssl_connection_t *
ssl_connect(uint32_t port);

bool
https_check(uint32_t port);

void
ssl_free(void);

void
ssl_connection_destroy(ssl_connection_t *conn);

/* vim: set et sw=4 sts=4 tw=80: */
