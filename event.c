#include "event.h"

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
        perror("nyx: socket");
        return -1;
    }

    addr.nl_family = AF_NETLINK;
    addr.nl_groups = CN_IDX_PROC;
    addr.nl_pid = getpid();

    rc = bind(netlink_socket, (struct sockaddr *)&addr, sizeof(addr));

    if (rc == -1)
    {
        perror("nyx: bind");
        close(netlink_socket);
        return -1;
    }

    return netlink_socket;
}

/**
 * Subscribe on process events
 */
static int
set_process_event_listen(int nl_sock, bool enable)
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

    rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);

    if (rc == -1)
    {
        perror("nyx: send");
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

/**
 * Handle a single process event
 */
static int
handle_proc_ev(int nl_sock)
{
    int rc;

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

        if (rc == 0)
        {
            /* shutdown? */
            return 0;
        }
        else if (rc == -1)
        {
            if (errno == EINTR)
                continue;

            perror("nyx: recv");
            return -1;
        }

        switch (nlcn_msg.proc_ev.what)
        {
            /* we are interested in fork and exit only */
            case PROC_EVENT_FORK:
                printf("fork: parent tid=%d pid=%d -> child tid=%d pid=%d\n",
                        nlcn_msg.proc_ev.event_data.fork.parent_pid,
                        nlcn_msg.proc_ev.event_data.fork.parent_tgid,
                        nlcn_msg.proc_ev.event_data.fork.child_pid,
                        nlcn_msg.proc_ev.event_data.fork.child_tgid);
                break;
            case PROC_EVENT_EXIT:
                printf("exit: tid=%d pid=%d exit_code=%d\n",
                        nlcn_msg.proc_ev.event_data.exit.process_pid,
                        nlcn_msg.proc_ev.event_data.exit.process_tgid,
                        nlcn_msg.proc_ev.event_data.exit.exit_code);
                break;
            case PROC_EVENT_NONE:
            case PROC_EVENT_EXEC:
            case PROC_EVENT_UID:
            case PROC_EVENT_GID:
            default:
                /* unhandled events */
                break;
        }
    }

    return 0;
}

static void
on_sigint(int unused)
{
    puts("SIGINT - exiting event loop");
    need_exit = true;
}

int
event_loop(void)
{
    int socket;
    int rc = 1;

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

    rc = handle_proc_ev(socket);
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
