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

#include "def.h"
#include "event.h"
#include "log.h"
#include "socket.h"

/* we want to include sys/socket.h before linux/netlink.h
 * to avoid some compilation problems with some 2.6 kernels */
#include <sys/socket.h>

#include <errno.h>
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NYX_MAX_EVENTS 16

static volatile bool need_exit = false;

/**
 * Open netlink socket connection
 */
static int32_t
netlink_connect(void)
{
    struct sockaddr_nl addr;

    int32_t netlink_socket = socket(
            PF_NETLINK,                /* kernel user interface device */
            SOCK_DGRAM | SOCK_CLOEXEC, /* datagram */
            NETLINK_CONNECTOR);        /* netlink */

    if (netlink_socket == -1)
    {
        log_perror("nyx: socket");
        return -1;
    }

    /* initialize memory */
    memset(&addr, 0, sizeof(struct sockaddr_nl));

    addr.nl_family = AF_NETLINK;
    addr.nl_groups = CN_IDX_PROC;
    addr.nl_pid = getpid();

    int32_t rc = bind(netlink_socket, (struct sockaddr *)&addr, sizeof(addr));

    if (rc == -1)
    {
        log_perror("nyx: bind");
        close(netlink_socket);
        return -1;
    }

    return netlink_socket;
}

/**
 * Subscribe on process events
 */
static bool
set_process_event_listen(int32_t sock, bool enable)
{
    struct __attribute__ ((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__))
        {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        } data;
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    /* connect to process events */
    nlcn_msg.data.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.data.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.data.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    /* either start or stop listening to events */
    nlcn_msg.data.cn_mcast =
        enable
        ? PROC_CN_MCAST_LISTEN
        : PROC_CN_MCAST_IGNORE;

    int32_t rc = send(sock, &nlcn_msg, sizeof(nlcn_msg), 0);

    if (rc == -1)
    {
        log_perror("nyx: send");
        return false;
    }

    return true;
}

static bool
subscribe_event_listen(int32_t sock)
{
    return set_process_event_listen(sock, true);
}

static bool
unsubscribe_event_listen(int32_t sock)
{
    return set_process_event_listen(sock, false);
}

static process_event_data_t *
new_event_data(void)
{
    process_event_data_t *data = xcalloc(1, sizeof(process_event_data_t));

    return data;
}

static int32_t
set_event_data(process_event_data_t *data, struct proc_event *event)
{
    switch (event->what)
    {
        case PROC_EVENT_FORK:
            data->type = EVENT_FORK;

            data->data.fork.parent_pid = event->event_data.fork.parent_pid;
            data->data.fork.parent_thread_group_id = event->event_data.fork.parent_tgid;
            data->data.fork.child_pid = event->event_data.fork.child_pid;
            data->data.fork.child_thread_group_id = event->event_data.fork.child_tgid;

            log_debug("fork: parent tid=%d pid=%d -> child tid=%d pid=%d",
                    event->event_data.fork.parent_pid,
                    event->event_data.fork.parent_tgid,
                    event->event_data.fork.child_pid,
                    event->event_data.fork.child_tgid);

            return data->data.fork.parent_pid;

        case PROC_EVENT_EXIT:
            data->type = EVENT_EXIT;

            data->data.exit.pid = event->event_data.exit.process_pid;
            data->data.exit.exit_code = event->event_data.exit.exit_code;
            data->data.exit.exit_signal = event->event_data.exit.exit_signal;
            data->data.exit.thread_group_id = event->event_data.exit.process_tgid;

            log_debug("exit: tid=%d pid=%d exit_code=%d",
                    event->event_data.exit.process_pid,
                    event->event_data.exit.process_tgid,
                    event->event_data.exit.exit_code);

            return data->data.exit.pid;

        /* unhandled events */
        case PROC_EVENT_NONE:
        case PROC_EVENT_EXEC:
        case PROC_EVENT_UID:
        case PROC_EVENT_GID:
        default:
            break;
    }

    return 0;
}

static void handle_eventfd(struct epoll_event *event, nyx_t *nyx)
{
    epoll_extra_data_t *extra = event->data.ptr;

    log_debug("Received epoll event on eventfd interface (%d)", nyx->event);

    uint64_t value = 0;
    int32_t err = read(extra->fd, &value, sizeof(value));

    if (err == -1)
        log_perror("nyx: read");

    need_exit = true;
}

/**
 * Handle a single process event
 */
static bool
handle_process_event(int32_t nl_sock, nyx_t *nyx, process_handler_t handler)
{
    bool success = false;

    struct epoll_event base_ev, fd_ev;
    struct epoll_event *events = NULL;

    process_event_data_t *event_data = new_event_data();

    struct __attribute__ ((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__))
        {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        } data;
    } nlcn_msg;

    log_debug("Starting event manager loop");

    /* initialize epoll */
    int32_t epfd = epoll_create(NYX_MAX_EVENTS);
    if (epfd == -1)
    {
        log_perror("nyx: epoll_create");
        goto teardown;
    }

    if (!unblock_socket(nl_sock))
        goto teardown;

    if (!add_epoll_socket(nl_sock, &base_ev, epfd, 0))
        goto teardown;

    /* add eventfd socket to epoll as well */
    if (nyx->event > 0)
    {
        if (!unblock_socket(nyx->event))
            goto teardown;

        if (!add_epoll_socket(nyx->event, &fd_ev, epfd, 0))
            goto teardown;
    }

    events = xcalloc(NYX_MAX_EVENTS, sizeof(struct epoll_event));

    while (!need_exit)
    {
        int32_t i = 0;
        struct epoll_event *event = NULL;

        int32_t n = epoll_wait(epfd, events, NYX_MAX_EVENTS, -1);

        for (i = 0, event = events; i < n; event++, i++)
        {
            epoll_extra_data_t *extra = event->data.ptr;
            int32_t fd = extra->fd;

            /* handle eventfd */
            if (fd == nyx->event)
            {
                handle_eventfd(event, nyx);
                success = true;
            }
            else
            {
                success = true;
                int32_t rc = recv(fd, &nlcn_msg, sizeof(nlcn_msg), 0);

                /* socket shutdown */
                if (rc == 0)
                {
                    success = true;
                    break;
                }
                else if (rc == -1)
                {
                    /* interrupted by a signal */
                    if (errno == EINTR)
                    {
                        success = true;
                        continue;
                    }

                    log_perror("nyx: recv");
                    break;
                }

                int32_t pid = set_event_data(event_data,
                        (struct proc_event *)(void *)&(nlcn_msg.data.proc_ev));

                if (pid > 0)
                    handler(pid, event_data, nyx);
            }
        }
    }

teardown:
    if (event_data != NULL)
    {
        free(event_data);
        event_data = NULL;
    }

    if (events != NULL)
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

    if (epfd > 0)
        close(epfd);

    return success;
}

static void
on_terminate(UNUSED int signum)
{
    log_debug("Caught termination signal - exiting event manager loop");

    /* setting this one won't do the trick until the
     * blocking receive returns */
    need_exit = true;
}

bool
event_loop(nyx_t *nyx, process_handler_t handler)
{
    /* reset exit state in case this is a restart */
    need_exit = false;

    int32_t sock = netlink_connect();
    if (sock == -1)
        return false;

    bool success = subscribe_event_listen(sock);
    if (!success)
        goto out;

    /* register termination handler */
    setup_signals(nyx, on_terminate);

    /* start listening on process events */
    success = handle_process_event(sock, nyx, handler);
    if (!success)
        goto out;

    unsubscribe_event_listen(sock);

out:
    close(sock);

    log_debug("Event manager: terminated");
    return success;
}

/* vim: set et sw=4 sts=4 tw=80: */
