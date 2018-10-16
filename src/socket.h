/* Copyright 2014-2018 Gregor Uhlenheuer
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

#include <stdbool.h>

/* epoll or kqueue */
#ifndef OSX
#include <sys/epoll.h>

#define NYX_EV_TYPE struct epoll_event
#define NYX_EV_GET(x) (x->data.ptr)

#else
#include <sys/event.h>

#define NYX_EV_TYPE struct kevent
#define NYX_EV_GET(x) (x->udata)

#endif

typedef enum
{
    HTTP_GET,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_POST,
    HTTP_PUT,
    HTTP_TRACE,
} http_method_e;

typedef struct
{
    int32_t fd;
    int32_t remote_socket;
    char *buffer;
    uint32_t pos;
    uint32_t length;
} epoll_extra_data_t;

http_method_e
http_method_from_string(const char *str);

const char *
http_method_to_string(http_method_e method);

ssize_t
send_status_safe(int32_t sock, int32_t status);

ssize_t
send_safe(int32_t sock, const void *buffer, size_t length);

bool
check_port(uint16_t port);

bool
check_http(const char *url, uint16_t port, http_method_e method);

bool
unblock_socket(int32_t sock);

bool
add_epoll_socket(int32_t sock, NYX_EV_TYPE *event, int32_t epoll, int32_t remote);

epoll_extra_data_t *
epoll_extra_data_new(int32_t fd, int32_t remote);

/* vim: set et sw=4 sts=4 tw=80: */
