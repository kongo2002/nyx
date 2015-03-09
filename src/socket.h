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

#ifndef __NYX_SOCKET_H__
#define __NYX_SOCKET_H__

#include <sys/epoll.h>

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

int
check_port(unsigned port);

int
check_http(const char *url, unsigned port);

int
unblock_socket(int socket);

int
add_epoll_socket(int socket, struct epoll_event *event, int epoll);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
