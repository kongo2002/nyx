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

#include "command.h"
#include "def.h"
#include "log.h"
#include "state.h"
#include "utils.h"
#include "watch.h"

#include <inttypes.h>

typedef void (* status_handler_t)(sender_callback_t *, nyx_t *, state_t *);

static bool
handle_all_by_handler(sender_callback_t *cb, nyx_t *nyx, status_handler_t handler)
{
    if (!nyx->states)
        return false;

    list_node_t *node = nyx->states->head;

    while (node)
    {
        state_t *state = node->data;

        handler(cb, nyx, state);

        node = node->next;
    }

    return true;
}

static bool
handle_status_change_all(sender_callback_t *cb, nyx_t *nyx, state_e new_state)
{
    if (!nyx->states)
        return false;

    list_node_t *node = nyx->states->head;

    while (node)
    {
        state_t *state = node->data;

        set_state_command(state, new_state);
        cb->sender(cb, "requested %s for watch '%s'",
                state_to_human_string(new_state),
                state->watch->name);

        node = node->next;
    }

    return true;
}

static bool
handle_status_change(sender_callback_t *cb, const char **input, nyx_t *nyx, state_e new_state)
{
    const char *name = input[1];

    if (is_all(name))
        return handle_status_change_all(cb, nyx, new_state);

    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return false;
    }

    /* request state change */
    set_state_command(state, new_state);
    cb->sender(cb, "requested %s for watch '%s'",
            state_to_human_string(new_state),
            name);

    return true;
}

static void
send_strings(sender_callback_t *cb, const char *name, const char **strings)
{
    const char **string = strings;

    if (string == NULL || *string == NULL)
        return;

    cb->sender(cb, "%s:", name);

    while (*string)
    {
        cb->sender(cb, "  '%s'", *string);
        string++;
    }
}

static void
send_keys(sender_callback_t *cb, const char *name, hash_t *keys)
{
    if (keys == NULL || hash_count(keys) < 1)
        return;

    cb->sender(cb, "%s:", name);

    const char *key = NULL;
    void *data = NULL;
    hash_iter_t *iter = hash_iter_start(keys);

    while (hash_iter(iter, &key, &data))
    {
        const char *value = data;

        cb->sender(cb, "  %s: %s", key, value);
    }

    free(iter);
}

static bool
handle_config(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    const char *name = input[1];
    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return false;
    }

    watch_t *watch = state->watch;

    cb->sender(cb, "name: %s", name);

    send_strings(cb, "start", watch->start);
    send_strings(cb, "stop", watch->stop);

    if (watch->stop_timeout)
        cb->sender(cb, "stop_timeout: %u", watch->stop_timeout);

    if (watch->dir)
        cb->sender(cb, "dir: %s", watch->dir);

    if (watch->uid)
        cb->sender(cb, "uid: %s", watch->uid);

    if (watch->gid)
        cb->sender(cb, "gid: %s", watch->gid);

    if (watch->log_file)
        cb->sender(cb, "log_file: %s", watch->log_file);

    if (watch->error_file)
        cb->sender(cb, "error_file: %s", watch->error_file);

    if (watch->max_memory)
        cb->sender(cb, "max_memory: %" PRIu64, watch->max_memory);

    if (watch->max_cpu)
        cb->sender(cb, "max_cpu: %u", watch->max_cpu);

    if (watch->port_check)
        cb->sender(cb, "port_check: %u", watch->port_check);

    if (watch->http_check)
    {
        cb->sender(cb, "http_check: %s", watch->http_check);
        cb->sender(cb, "http_check_method: %s",
                http_method_to_string(watch->http_check_method));
        cb->sender(cb, "http_check_port: %u",
                watch->http_check_port ? watch->http_check_port : 80);
    }

    cb->sender(cb, "startup_delay: %u", watch->startup_delay);

    send_keys(cb, "env", watch->env);

    return true;
}

static bool
handle_history(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    const char *name = input[1];
    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return false;
    }

    if (state->history->count < 1)
        return true;

    uint32_t i = state->history->count;

    while (i-- > 0)
    {
        timestack_elem_t *elem = &state->history->elements[i];
        struct tm *ltime = localtime(&elem->time);

        cb->sender(cb, "%04d-%02d-%02dT%02d:%02d:%02d: %s",
            ltime->tm_year + 1900,
            ltime->tm_mon + 1,
            ltime->tm_mday,
            ltime->tm_hour,
            ltime->tm_min,
            ltime->tm_sec,
            state_to_human_string(elem->value));
    }

    return true;
}

static bool
handle_ping(sender_callback_t *cb, UNUSED const char **input, UNUSED nyx_t *nyx)
{
    return cb->sender(cb, "pong") > 0;
}

static bool
handle_version(sender_callback_t *cb, UNUSED const char **input, UNUSED nyx_t *nyx)
{
    return cb->sender(cb, NYX_VERSION) > 0;
}

static bool
handle_terminate(sender_callback_t *cb, UNUSED const char **input, nyx_t *nyx)
{
    /* trigger the eventfd */
    signal_eventfd(4, nyx);

    /* trigger the termination handler (if specified) */
    if (nyx->terminate_handler)
        nyx->terminate_handler(0);

    return cb->sender(cb, "ok") > 0;
}

static bool
handle_quit(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    if (nyx->states)
    {
        list_node_t *node = nyx->states->head;

        /* first we trigger the stop signal on all states */
        while (node)
        {
            state_t *state = node->data;

            set_state_command(state, STATE_STOPPING);

            node = node->next;
        }
    }

    /* after that we execute the termination handler */
    return handle_terminate(cb, input, nyx);
}

static bool
handle_stop(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    return handle_status_change(cb, input, nyx, STATE_STOPPING);
}

static bool
handle_restart(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    return handle_status_change(cb, input, nyx, STATE_RESTARTING);
}

static bool
handle_start(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    return handle_status_change(cb, input, nyx, STATE_STARTING);
}

static bool
handle_watches(sender_callback_t *cb, UNUSED const char **input, nyx_t *nyx)
{
    if (!nyx->states)
        return false;

    list_node_t *node = nyx->states->head;

    while (node)
    {
        state_t *state = node->data;

        if (!state)
            continue;

        cb->sender(cb, "%s", state->watch->name);

        node = node->next;
    }

    return true;
}

static bool
handle_reload(sender_callback_t *cb, UNUSED const char **input, nyx_t *nyx)
{
    if (!nyx->options.config_file)
    {
        cb->sender(cb, "no config file to reload");
        return false;
    }

    if (!nyx_reload(nyx))
    {
        cb->sender(cb, "failed to reload config");
        return false;
    }

    cb->sender(cb, "ok");
    return true;
}

static void
print_status(sender_callback_t *cb, UNUSED nyx_t *nyx, state_t *state)
{
    const char *name = state->watch->name;

    /* print pid if running */
    if (state->state == STATE_RUNNING && state->pid)
    {
        cb->sender(cb, "%s: %s (PID %d)",
                name,
                state_to_human_string(state->state),
                state->pid);
    }
    else
        cb->sender(cb, "%s: %s", name, state_to_human_string(state->state));
}

static bool
handle_status(sender_callback_t *cb, const char **input, nyx_t *nyx)
{
    const char *name = input[1];

    if (is_all(name))
        return handle_all_by_handler(cb, nyx, print_status);

    state_t *state = hash_get(nyx->state_map, name);

    if (state == NULL)
    {
        cb->sender(cb, "unknown watch '%s'", name);
        return false;
    }

    print_status(cb, nyx, state);

    return true;
}

#define CMD(t, n, h, a, d) \
    { .type = t, .name = n, .handler = h, .min_args = a, .cmd_length = LEN(n), \
      .description = d }

static command_t commands[] =
{
    CMD(CMD_PING,       "ping",       handle_ping,       0,
            "ping the nyx server"),
    CMD(CMD_VERSION,    "version",    handle_version,    0,
            "request the nyx server version"),
    CMD(CMD_WATCHES,    "watches",    handle_watches,    0,
            "get the list of watches"),
    CMD(CMD_START,      "start",      handle_start,      1,
            "start the specified watch"),
    CMD(CMD_STOP,       "stop",       handle_stop,       1,
            "stop the specified watch"),
    CMD(CMD_RESTART,    "restart",    handle_restart,    1,
            "restart the specified watch"),
    CMD(CMD_STATUS,     "status",     handle_status,     1,
            "request the watch's status"),
    CMD(CMD_HISTORY,    "history",    handle_history,    1,
            "get the latest events of the specified watch"),
    CMD(CMD_CONFIG,     "config",     handle_config,     1,
            "get the configuration of the specified watch"),
    CMD(CMD_RELOAD,     "reload",     handle_reload,     0,
            "reload the nyx configuration"),
    CMD(CMD_TERMINATE,  "terminate",  handle_terminate,  0,
            "terminate the nyx server"),
    CMD(CMD_QUIT,       "quit",       handle_quit,       0,
            "stop the nyx server and all watched processes")
};

#undef CMD

static size_t
command_max_length(void)
{
    size_t idx = 0, len = 0;

    while (idx < CMD_SIZE)
    {
        size_t cmd_len = commands[idx++].cmd_length;
        len = MAX(len, cmd_len);
    }

    return len;
}

static void
print_command(FILE *out, size_t pad, command_t *cmd)
{
    fprintf(out, "  %s", cmd->name);

    for (uint32_t i = cmd->cmd_length; i < pad; i++)
        fputc(' ', out);

    fprintf(out, "%s\n", cmd->description);
}

void
print_commands(FILE *out)
{
    uint32_t idx = 0;
    size_t pad_to = command_max_length() + 2;

    while (idx < CMD_SIZE)
    {
        print_command(out, pad_to, &commands[idx++]);
    }
}

command_t *
parse_command(const char **input)
{
    size_t i = 0;
    size_t size = LEN(commands);
    uint32_t args = 0;
    command_t *command = commands;

    /* no input commands given at all */
    if (input == NULL)
        return NULL;

    while (i < size)
    {
        if (!strncmp(command->name, *input, command->cmd_length))
        {
            /* check if necessary arguments are given */
            args = count_args(input) - 1;

            if (args < command->min_args)
            {
                log_error("Command '%s' requires a minimum of %d arguments",
                        command->name,
                        command->min_args);
                return NULL;
            }

            return command;
        }

        command++; i++;
    }

    return NULL;
}

/* vim: set et sw=4 sts=4 tw=80: */
