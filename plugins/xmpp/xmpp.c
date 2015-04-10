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
#include "hash.h"
#include "log.h"
#include "plugins.h"
#include "state.h"
#include "utils.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <strophe.h>
#include <sys/types.h>

typedef enum
{
    NYX_XMPP_STARTUP,
    NYX_XMPP_CONNECTED,
    NYX_XMPP_DISCONNECTED,
    NYX_XMPP_SHUTDOWN
} xmpp_state_e;

typedef struct
{
    xmpp_state_e state;
    const char *jid;
    const char *pass;
    const char *recipient;
    const char *host;
    const char *groupchat;
    int reconnect_timeout;
    int debug;
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    pthread_t *xmpp_thread;
} xmpp_info_t;

static xmpp_stanza_t *
get_stanza(const char *name, xmpp_ctx_t *ctx)
{
    xmpp_stanza_t *stanza = xmpp_stanza_new(ctx);

    xmpp_stanza_set_name(stanza, name);

    return stanza;
}

static void
send_groupchat(xmpp_info_t *info, const char *message)
{
    xmpp_stanza_t *mess = get_stanza("message", info->ctx);
    xmpp_stanza_set_type(mess, "groupchat");
    xmpp_stanza_set_attribute(mess, "lang", "en");

    xmpp_stanza_set_attribute(mess, "from", info->jid);
    xmpp_stanza_set_attribute(mess, "to", info->groupchat);

    xmpp_stanza_t *body = get_stanza("body", info->ctx);

    xmpp_stanza_t *text = xmpp_stanza_new(info->ctx);
    xmpp_stanza_set_text(text, message);

    xmpp_stanza_add_child(body, text);
    xmpp_stanza_add_child(mess, body);

    xmpp_send(info->conn, mess);
    xmpp_stanza_release(mess);
}

static void
send_chat(xmpp_info_t *info, const char *message)
{
    xmpp_stanza_t *mess = get_stanza("message", info->ctx);
    xmpp_stanza_set_type(mess, "chat");
    xmpp_stanza_set_attribute(mess, "lang", "en");

    xmpp_stanza_set_attribute(mess, "from", info->jid);
    xmpp_stanza_set_attribute(mess, "to", info->recipient);

    xmpp_stanza_t *body = get_stanza("body", info->ctx);

    xmpp_stanza_t *text = xmpp_stanza_new(info->ctx);
    xmpp_stanza_set_text(text, message);

    xmpp_stanza_add_child(body, text);
    xmpp_stanza_add_child(mess, body);

    xmpp_send(info->conn, mess);
    xmpp_stanza_release(mess);
}

static void
handle_state_change(const char *name, int state, pid_t pid, void *userdata)
{
    char buffer[512] = {0};
    xmpp_info_t *info = userdata;

    if (info == NULL || info->state != NYX_XMPP_CONNECTED)
        return;

    snprintf(buffer, LEN(buffer), "Watch '%s' changed state to %s [%d]",
            name, state_to_human_string(state), pid);

    if (info->recipient)
        send_chat(info, buffer);

    if (info->groupchat)
        send_groupchat(info, buffer);
}

static void
handle_destroy_callback(void *userdata)
{
    if (userdata == NULL)
        return;

    xmpp_info_t *info = userdata;

    if (info->conn)
    {
        xmpp_disconnect(info->conn);

        /* send SIGTERM to interrupt the select() */
        if (info->state == NYX_XMPP_DISCONNECTED)
            pthread_kill(*info->xmpp_thread, SIGTERM);

        info->state = NYX_XMPP_SHUTDOWN;

        pthread_join(*info->xmpp_thread, NULL);

        xmpp_conn_release(info->conn);
    }

    if (info->ctx)
        xmpp_ctx_free(info->ctx);

    xmpp_shutdown();

    free(info->xmpp_thread);
    free(info);
}

static void
connection_handler(xmpp_conn_t * const conn,
        const xmpp_conn_event_t status,
        UNUSED const int error,
        UNUSED xmpp_stream_error_t * const stream_error,
        void * const udata)
{
    xmpp_info_t *info = udata;

    if (status == XMPP_CONN_CONNECT)
    {
        /* send initial presence stanza */
        xmpp_stanza_t *pres = get_stanza("presence", info->ctx);
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);

        /* join groupchat (if configured) */
        if (info->groupchat)
        {
            char buffer[512] = {0};

            snprintf(buffer, LEN(buffer), "%s/nyx", info->groupchat);

            xmpp_stanza_t *grp = get_stanza("presence", info->ctx);
            xmpp_stanza_set_attribute(grp, "from", info->jid);
            xmpp_stanza_set_attribute(grp, "to", buffer);

            xmpp_stanza_t *x = get_stanza("x", info->ctx);
            xmpp_stanza_set_ns(x, "http://jabber.org/protocol/muc");

            xmpp_stanza_add_child(grp, x);

            xmpp_send(conn, grp);
            xmpp_stanza_release(grp);
        }

        info->state = NYX_XMPP_CONNECTED;

        log_info("xmpp: successfully connected");
    }
    else
    {
        info->state = NYX_XMPP_DISCONNECTED;

        if (info->debug)
            log_info("xmpp: connection closed");
    }
}

static int
reconnect_loop(xmpp_info_t *info)
{
    info->state = NYX_XMPP_STARTUP;

    if (info->debug)
        log_info("xmpp: trying to connect...");

    /* for some reason we have to dispose the connection instance
     * before trying a reconnect */
    if (info->conn)
    {
        xmpp_conn_release(info->conn);
        info->conn = NULL;
    }

    info->conn = xmpp_conn_new(info->ctx);

    xmpp_conn_set_jid(info->conn, info->jid);
    xmpp_conn_set_pass(info->conn, info->pass);

    int res = xmpp_connect_client(info->conn, info->host, 0, connection_handler, info);

    if (res == -1)
    {
        log_warn("xmpp: connect failed");
        return 0;
    }

    /* start event loop */
    while (info->state == NYX_XMPP_STARTUP || info->state == NYX_XMPP_CONNECTED)
    {
        /* 100 milliseconds should be sufficient */
        xmpp_run_once(info->ctx, 100);
    }

    return info->state != NYX_XMPP_SHUTDOWN;
}

static void *
start_thread(void *obj)
{
    xmpp_info_t *info = obj;

    while (info->state != NYX_XMPP_SHUTDOWN && reconnect_loop(info))
    {
        if (info->debug)
            log_info("xmpp: waiting for %ds to reconnect", info->reconnect_timeout);

        wait_interval(info->reconnect_timeout);
    }

    log_info("xmpp: terminating");

    return NULL;
}

int
plugin_init(plugin_manager_t *manager)
{
    const char *jid = NULL, *pass = NULL, *recipient = NULL, *groupchat = NULL;
    const char *reconnect = NULL, *debug = NULL;

    /* look for mandatory config values */
    jid = hash_get(manager->config, "xmpp_jid");
    pass = hash_get(manager->config, "xmpp_password");
    recipient = hash_get(manager->config, "xmpp_recipient");
    groupchat = hash_get(manager->config, "xmpp_groupchat");

    if (jid == NULL || pass == NULL ||
            (recipient == NULL && groupchat == NULL))
    {
        log_warn("xmpp plugin: mandatory config values 'xmpp_jid', 'xmpp_password',"
                " 'xmpp_recipient' or 'xmpp_groupchat' missing");
        return 0;
    }

    reconnect = hash_get(manager->config, "xmpp_reconnect_timeout");
    debug = hash_get(manager->config, "xmpp_debug");

    xmpp_info_t *info = xcalloc1(sizeof(xmpp_info_t));

    info->jid = jid;
    info->pass = pass;
    info->recipient = recipient;
    info->groupchat = groupchat;
    info->host = hash_get(manager->config, "xmpp_host");

    /* default reconnect timeout of 60 seconds */
    info->reconnect_timeout = 60;

    if (reconnect && *reconnect != '\0')
        info->reconnect_timeout = atoi(reconnect);

    /* minimum of 5 seconds reconnect timeout */
    info->reconnect_timeout = MAX(5, info->reconnect_timeout);

    info->debug = debug && *debug != '\0';

    /* initialize library */
    xmpp_initialize();

    xmpp_log_t *logger = info->debug
        ? xmpp_get_default_logger(XMPP_LEVEL_DEBUG)
        : NULL;

    info->ctx = xmpp_ctx_new(NULL, logger);
    info->xmpp_thread = xcalloc1(sizeof(pthread_t));

    int err = pthread_create(info->xmpp_thread, NULL, start_thread, info);

    if (err)
    {
        xmpp_ctx_free(info->ctx);

        free(info->xmpp_thread);
        free(info);

        xmpp_shutdown();

        return 0;
    }

    /* register callback functions */
    plugin_register_state_callback(manager, handle_state_change, info);
    plugin_register_destroy_callback(manager, handle_destroy_callback, info);

    return 1;
}

/* vim: set et sw=4 sts=4 tw=80: */
