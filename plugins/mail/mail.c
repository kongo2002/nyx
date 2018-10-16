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

#include "def.h"
#include "hash.h"
#include "log.h"
#include "plugins.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define CRLF "\r\n"

#define MAIL_TEMPLATE \
    "Date: %s" CRLF \
    "To: <%s>" CRLF \
    "From: <%s>(nyx)" CRLF \
    "Subject: %s" CRLF \
    CRLF \
    "%s: %s" CRLF

typedef struct
{
    const char *from;
    const char *to;
    const char *server;
    const char *user;
    const char *password;
} mail_ctx_t;

typedef struct
{
    size_t sent_bytes;
    size_t length;
    char *msg;
} mail_msg_t;

static size_t
send_payload(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    mail_msg_t *msg = userdata;
    size_t buffer_size = size * nmemb;

    if (buffer_size < 1)
        return 0;

    if (msg->sent_bytes >= msg->length)
        return 0;

    /* copy message into target buffer */
    size_t to_send = msg->length - msg->sent_bytes;
    size_t send = MIN(buffer_size, to_send);

    memcpy(ptr, msg->msg + msg->sent_bytes, send);

    msg->sent_bytes += send;

    return send;
}

static void
handle_state(const char *name, int state, pid_t pid, void *userdata)
{
    static const size_t length = 1024;
    mail_ctx_t *ctx = userdata;

    if (!ctx)
        return;

    CURL *curl = curl_easy_init();
    CURLcode code = CURLE_OK;

    if (!curl)
        return;

    mail_msg_t *msg = xcalloc1(sizeof(mail_msg_t));

    msg->length = length;
    msg->msg = xcalloc(length, sizeof(char));

    /* build message */

    char date[64] = {0};
    char message[128] = {0};

    time_t now = time(NULL);
    struct tm *local = localtime(&now);

    strftime(date, LEN(date), "%d %b %Y %H:%M:%S %z", local);

    if (pid)
    {
        snprintf(message, LEN(message),
                "Watch '%s' [%d] changed state to %d", name, pid, state);
    }
    else
    {
        snprintf(message, LEN(message),
                "Watch '%s' changed state to %d", name, state);
    }

    msg->length = snprintf(msg->msg,
            length, MAIL_TEMPLATE, date, ctx->to, ctx->from, message, date, message);

    /* configure curl handle */

    curl_easy_setopt(curl, CURLOPT_URL, ctx->server);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

    curl_easy_setopt(curl, CURLOPT_USERNAME, ctx->user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, ctx->password);

    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, ctx->from);

    struct curl_slist *recipients = NULL;
    recipients = curl_slist_append(recipients, ctx->to);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_payload);
    curl_easy_setopt(curl, CURLOPT_READDATA, msg);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    code = curl_easy_perform(curl);

    if (code != CURLE_OK)
    {
        log_warn("mail delivery via curl failed: %s", curl_easy_strerror(code));
    }

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

    free(msg->msg);
    free(msg);
}

static void
handle_destroy(void *userdata)
{
    if (userdata)
    {
        mail_ctx_t *ctx = userdata;

        free(ctx);
    }
}

int
plugin_init(plugin_manager_t *manager)
{
    hash_t *cfg = manager->config;

    if (!cfg)
    {
        log_warn("mail: necessary config options missing");
        return 0;
    }

    mail_ctx_t *ctx = xcalloc1(sizeof(mail_ctx_t));

    ctx->user = hash_get(cfg, "mail_user");
    ctx->password = hash_get(cfg, "mail_password");
    ctx->server = hash_get(cfg, "mail_server");
    ctx->from = hash_get(cfg, "mail_from");
    ctx->to = hash_get(cfg, "mail_to");

    if (!ctx->user ||
        !ctx->password ||
        !ctx->server ||
        !ctx->from ||
        !ctx->to)
    {
        log_warn("Any of the mandatory settings 'mail_user', "
                "'mail_password', 'mail_from', 'mail_to' and/or "
                "'mail_server' is missing.");

        return 0;
    }

    plugin_register_state_callback(manager, handle_state, ctx);
    plugin_register_destroy_callback(manager, handle_destroy, ctx);

    return 1;
}

#undef CRLF
#undef MAIL_TEMPLATE

/* vim: set et sw=4 sts=4 tw=80: */
