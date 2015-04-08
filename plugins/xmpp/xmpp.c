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

#include <pthread.h>
#include <stdio.h>
#include <strophe.h>
#include <sys/types.h>

typedef enum
{
    NYX_XMPP_STARTUP,
    NYX_XMPP_CONNECTED,
    NYX_XMPP_DISCONNECTED
} xmpp_state_e;

typedef struct
{
    xmpp_state_e state;
    const char *jid;
    const char *pass;
    const char *recipient;
    const char *host;
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
handle_state_change(const char *name, int state, pid_t pid, void *userdata)
{
    char buffer[512] = {0};
    xmpp_info_t *info = userdata;

    if (info == NULL || info->state != NYX_XMPP_CONNECTED)
        return;

    snprintf(buffer, LEN(buffer), "Watch '%s' changed state to %s [%d]",
            name, state_to_human_string(state), pid);

    xmpp_stanza_t *mess = get_stanza("message", info->ctx);
    xmpp_stanza_set_type(mess, "chat");
    xmpp_stanza_set_attribute(mess, "lang", "en");

    xmpp_stanza_set_attribute(mess, "from", info->jid);
    xmpp_stanza_set_attribute(mess, "to", info->recipient);

    xmpp_stanza_t *body = get_stanza("body", info->ctx);

    xmpp_stanza_t *text = xmpp_stanza_new(info->ctx);
    xmpp_stanza_set_text(text, buffer);

    xmpp_stanza_add_child(body, text);
    xmpp_stanza_add_child(mess, body);

    xmpp_send(info->conn, mess);
    xmpp_stanza_release(mess);
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

        info->state = NYX_XMPP_DISCONNECTED;

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

        info->state = NYX_XMPP_CONNECTED;

        xmpp_stanza_release(pres);
    }
    else
    {
        info->state = NYX_XMPP_DISCONNECTED;

        log_info("xmpp connection closed");
    }
}

static void *
start_thread(void *obj)
{
    xmpp_info_t *info = obj;

    int res = xmpp_connect_client(info->conn, info->host, 0, connection_handler, info);

    if (res == -1)
    {
        log_warn("XMPP connect failed");
        return NULL;
    }

    /* start event loop */
    while (info->state == NYX_XMPP_STARTUP || info->state == NYX_XMPP_CONNECTED)
    {
        /* 100 milliseconds should be sufficient */
        xmpp_run_once(info->ctx, 100);
    }

    return NULL;
}

static log_level_e
to_level(xmpp_log_level_t level)
{
    switch (level)
    {
        case XMPP_LEVEL_INFO:
            return NYX_LOG_INFO;
        case XMPP_LEVEL_WARN:
            return NYX_LOG_WARN;
        case XMPP_LEVEL_ERROR:
            return NYX_LOG_ERROR;
        case XMPP_LEVEL_DEBUG:
            return NYX_LOG_DEBUG;
        default:
            return NYX_LOG_INFO;
    }
}

static void
log_xmpp(UNUSED void *const userdata, const xmpp_log_level_t level, const char *const area, const char *const msg)
{
    log_message(to_level(level), "xmpp [%s]: %s ", area, msg);
}

int
plugin_init(plugin_manager_t *manager)
{
    const char *jid = NULL, *pass = NULL, *recipient = NULL, *host = NULL;
    xmpp_log_t *logger = NULL;

    /* look for mandatory config values */
    jid = hash_get(manager->config, "xmpp_jid");
    pass = hash_get(manager->config, "xmpp_password");
    recipient = hash_get(manager->config, "xmpp_recipient");
    host = hash_get(manager->config, "xmpp_host");

    if (jid == NULL || pass == NULL || recipient == NULL)
    {
        log_warn("xmpp plugin: mandatory config values 'xmpp_jid', 'xmpp_password'"
                " and/or 'xmpp_recipient' missing");
        return 0;
    }

    xmpp_info_t *info = xcalloc1(sizeof(xmpp_info_t));

    info->jid = jid;
    info->pass = pass;
    info->recipient = recipient;
    info->host = host;

    /* initialize library */
    xmpp_initialize();

    /* build logger interface */
    logger = xcalloc1(sizeof(xmpp_log_t));
    logger->handler = log_xmpp;

    info->ctx = xmpp_ctx_new(NULL, logger);
    info->conn = xmpp_conn_new(info->ctx);

    xmpp_conn_set_jid(info->conn, info->jid);
    xmpp_conn_set_pass(info->conn, info->pass);

    info->xmpp_thread = xcalloc1(sizeof(pthread_t));

    int err = pthread_create(info->xmpp_thread, NULL, start_thread, info);

    if (err)
    {
        free(info->xmpp_thread);
        free(info);
        free(logger);

        return 0;
    }

    /* register callback functions */
    plugin_register_state_callback(manager, handle_state_change, info);
    plugin_register_destroy_callback(manager, handle_destroy_callback, info);

    return 1;
}

/* vim: set et sw=4 sts=4 tw=80: */
