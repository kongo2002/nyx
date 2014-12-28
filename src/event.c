#include "def.h"
#include "event.h"
#include "log.h"

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static volatile bool need_exit = false;

/**
 * Open netlink socket connection
 */
static int
netlink_connect(void)
{
    int rc;
    int netlink_socket;
    struct sockaddr_nl addr;

    netlink_socket = socket(
            PF_NETLINK,         /* kernel user interface device */
            SOCK_DGRAM,         /* datagram */
            NETLINK_CONNECTOR); /* netlink */

    if (netlink_socket == -1)
    {
        log_perror("nyx: socket");
        return -1;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_groups = CN_IDX_PROC;
    addr.nl_pid = getpid();

    rc = bind(netlink_socket, (struct sockaddr *)&addr, sizeof(addr));

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
static int
set_process_event_listen(int socket, bool enable)
{
    int rc;

    struct __attribute__ ((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__))
        {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    /* connect to process events */
    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    /* either start or stop listening to events */
    nlcn_msg.cn_mcast =
        enable
        ? PROC_CN_MCAST_LISTEN
        : PROC_CN_MCAST_IGNORE;

    rc = send(socket, &nlcn_msg, sizeof(nlcn_msg), 0);

    if (rc == -1)
    {
        log_perror("nyx: send");
        return -1;
    }

    return 0;
}

static int
subscribe_event_listen(int socket)
{
    return set_process_event_listen(socket, true);
}

static int
unsubscribe_event_listen(int socket)
{
    return set_process_event_listen(socket, false);
}

static process_event_data_t *
new_event_data(void)
{
    process_event_data_t *data = calloc(1, sizeof(process_event_data_t));

    if (data == NULL)
        log_critical_perror("nyx: calloc");

    return data;
}

static int
set_event_data(process_event_data_t *data, struct proc_event *event)
{
    switch (event->what)
    {
        case PROC_EVENT_FORK:
            data->type = EVENT_FORK;

            data->fork.parent_pid = event->event_data.fork.parent_pid;
            data->fork.parent_thread_group_id = event->event_data.fork.parent_tgid;
            data->fork.child_pid = event->event_data.fork.child_pid;
            data->fork.child_thread_group_id = event->event_data.fork.child_tgid;

            log_debug("fork: parent tid=%d pid=%d -> child tid=%d pid=%d",
                    event->event_data.fork.parent_pid,
                    event->event_data.fork.parent_tgid,
                    event->event_data.fork.child_pid,
                    event->event_data.fork.child_tgid);

            return data->fork.parent_pid;

        case PROC_EVENT_EXIT:
            data->type = EVENT_EXIT;

            data->exit.pid = event->event_data.exit.process_pid;
            data->exit.exit_code = event->event_data.exit.exit_code;
            data->exit.exit_signal = event->event_data.exit.exit_signal;
            data->exit.thread_group_id = event->event_data.exit.process_tgid;

            log_debug("exit: tid=%d pid=%d exit_code=%d",
                    event->event_data.exit.process_pid,
                    event->event_data.exit.process_tgid,
                    event->event_data.exit.exit_code);

            return data->exit.pid;

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

/**
 * Handle a single process event
 */
static int
handle_process_event(int nl_sock, nyx_t *nyx, process_handler_t handler)
{
    int pid = 0, rc = 0;
    process_event_data_t *event_data = new_event_data();

    struct __attribute__ ((aligned(NLMSG_ALIGNTO)))
    {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__))
        {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;

    while (!need_exit)
    {
        rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);

        /* socket shutdown */
        if (rc == 0)
        {
            rc = 1;
            break;
        }
        else if (rc == -1)
        {
            /* interrupted by a signal */
            if (errno == EINTR)
            {
                rc = 1;
                continue;
            }

            log_perror("nyx: recv");
            break;
        }

        pid = set_event_data(event_data, &nlcn_msg.proc_ev);

        if (pid > 0)
            handler(pid, event_data, nyx);
    }

    if (event_data != NULL)
    {
        free(event_data);
        event_data = NULL;
    }

    return rc;
}

static void
on_sigint(UNUSED int unused)
{
    log_debug("SIGINT - exiting event loop");
    need_exit = true;
}

int
event_loop(nyx_t *nyx, process_handler_t handler)
{
    int socket;
    int rc = 1;

    /* TODO: does this belong in here? */
    signal(SIGINT, &on_sigint);
    siginterrupt(SIGINT, true);

    socket = netlink_connect();
    if (socket == -1)
        return 0;

    rc = subscribe_event_listen(socket);
    if (rc == -1)
    {
        rc = 0;
        goto out;
    }

    rc = handle_process_event(socket, nyx, handler);
    if (rc == -1)
    {
        rc = 0;
        goto out;
    }

    unsubscribe_event_listen(socket);

out:
    close(socket);
    return rc;
}

/* vim: set et sw=4 sts=4 tw=80: */
