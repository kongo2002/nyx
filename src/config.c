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

#define _GNU_SOURCE

#include "config.h"
#include "def.h"
#include "log.h"
#include "hash.h"
#include "nyx.h"
#include "utils.h"
#include "watch.h"

#include <string.h>

#define SCALAR_HANDLER(name_, func_) \
    { .key = name_, .handler = { func_, NULL, NULL } }

#define MAP_HANDLER(name_, func_) \
    { .key = name_, .handler = { NULL, NULL, func_ } }

#define HANDLERS(name_, sfunc_, lfunc_, mfunc_) \
    { .key = name_, .handler = { sfunc_, lfunc_, mfunc_ } }

static const char * yaml_event_names[] =
{
    "YAML_NO_EVENT",
    "YAML_STREAM_START_EVENT",
    "YAML_STREAM_END_EVENT",
    "YAML_DOCUMENT_START_EVENT",
    "YAML_DOCUMENT_END_EVENT",
    "YAML_ALIAS_EVENT",
    "YAML_SCALAR_EVENT",
    "YAML_SEQUENCE_START_EVENT",
    "YAML_SEQUENCE_END_EVENT",
    "YAML_MAPPING_START_EVENT",
    "YAML_MAPPING_END_EVENT"
};

struct watch_info
{
    watch_t *watch;
    struct config_parser_map *map;
};

static parse_info_t *
handle_mapping(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data);

static parse_info_t *
handle_scalar_key(parse_info_t *info, yaml_event_t *event, void *data);

static parse_info_t *
handle_scalar_value(parse_info_t *info, yaml_event_t *event, UNUSED void *data);

static parse_info_t *
handle_watch_map_key(parse_info_t *info, yaml_event_t *event, void *data);

static parse_info_t *
handle_watch(parse_info_t *info, yaml_event_t *event, UNUSED void *data);

static parse_info_t *
handle_watch_env_key(parse_info_t *info, yaml_event_t *event, UNUSED void *data);

static parse_info_t *
handle_nyx_key(parse_info_t *info, yaml_event_t *event, UNUSED void *data);

static parse_info_t *
handle_watch_http_check_key(parse_info_t *info, yaml_event_t *event, void *data);

static struct watch_info *
watch_info_new(watch_t *watch, struct config_parser_map *map)
{
    struct watch_info *info = xcalloc1(sizeof(struct watch_info));

    info->watch = watch;
    info->map = map;

    return info;
}

static int
check_event_type(yaml_event_t *event, yaml_event_type_t event_type)
{
    if (event->type != event_type)
    {
        log_debug("Expecting '%s', but found '%s'",
                yaml_event_names[event_type],
                yaml_event_names[event->type]);
        return 0;
    }

    return 1;
}

static const char *
get_scalar_value(yaml_event_t *event)
{
    if (!check_event_type(event, YAML_SCALAR_EVENT))
        return NULL;

    return (char *)event->data.scalar.value;
}

static handler_func_t *
get_handler_from_map(struct config_parser_map *map, const char *key)
{
    struct config_parser_map *mapping = map;

    while (mapping && mapping->key)
    {
        if (!strcmp(mapping->key, key))
            return mapping->handler;

        mapping++;
    }

    return NULL;
}

static void
reset_handlers(parse_info_t *info)
{
    size_t handler_size = sizeof(handler_func_t);
    memset(info->handler, 0, handler_size * PARSE_HANDLER_SIZE);
}

static parse_info_t *
parser_up(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    if (info->parent == NULL)
    {
        log_debug("topmost parser without parent - invalid config [%s]",
                yaml_event_names[event->type]);
        return NULL;
    }

    parse_info_t *parent = info->parent;
    free(info);

    return parent;
}

static parse_info_t *
handle_stream_end(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_stream: end");

    return info;
}

static parse_info_t *
handle_document_end(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_document: end");

    reset_handlers(info);
    info->handler[YAML_STREAM_END_EVENT] = handle_stream_end;

    return info;
}

static parse_info_t *
handle_scalar_value(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    if (event->type != YAML_SCALAR_EVENT)
    {
        log_debug("Expecting scalar value, but found '%s'",
                yaml_event_names[event->type]);
        return NULL;
    }

    log_debug("handle_scalar_value: '%s'", event->data.scalar.value);

    info->handler[YAML_SCALAR_EVENT] = handle_scalar_key;

    return info;
}

static parse_info_t *
handle_scalar_key(parse_info_t *info, yaml_event_t *event, void *data)
{
    const char *key;
    handler_func_t *handler = NULL;

    key = get_scalar_value(event);

    if (key == NULL)
        return NULL;

    /* handler lookup */
    if (data != NULL)
    {
        struct config_parser_map *map = data;
        handler = get_handler_from_map(map, key);
    }

    if (handler == NULL)
    {
        log_warn("Unknown config key '%s'", key);

        info->handler[YAML_SCALAR_EVENT] = handle_scalar_value;
        info->handler[YAML_MAPPING_START_EVENT] = handle_mapping;
    }
    else
    {
        handler_func_t scalar_handler = handler[CFG_SCALAR];

        if (scalar_handler == NULL)
            scalar_handler = handle_scalar_key;

        info->handler[YAML_SCALAR_EVENT] = scalar_handler;
        info->handler[YAML_MAPPING_START_EVENT] = handler[CFG_MAP];
        info->handler[YAML_SEQUENCE_START_EVENT] = handler[CFG_LIST];
    }

    return info;
}

static parse_info_t *
handle_mapping_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    log_debug("handle_mapping: end");

    parse_info_t *parent = parser_up(info, event, data);

    /* as soon as any mapping (known or unknown) ends
     * the next scalar value has to be a key */
    parent->handler[YAML_SCALAR_EVENT] = handle_scalar_key;

    return parent;
}

static parse_info_t *
handle_mapping(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_mapping: start");

    parse_info_t *new = parse_info_new_child(info);

    new->handler[YAML_SCALAR_EVENT] = handle_scalar_key;
    new->handler[YAML_MAPPING_END_EVENT] = handle_mapping_end;

    return new;
}

static parse_info_t *
handle_document(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_document: start");

    reset_handlers(info);
    info->handler[YAML_MAPPING_START_EVENT] = handle_mapping;
    info->handler[YAML_DOCUMENT_END_EVENT] = handle_document_end;

    return info;
}

static parse_info_t *
handle_stream(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_stream: start");

    reset_handlers(info);
    info->handler[YAML_DOCUMENT_START_EVENT] = handle_document;
    info->handler[YAML_STREAM_END_EVENT] = handle_stream_end;

    return info;
}

static unsigned int
uatoi(const char *str)
{
    int value = atoi(str);

    if (value < 0)
    {
        log_warn("Invalid numeric value: '%s'", str);
        return 0;
    }

    return value;
}

#define DECLARE_WATCH_STR_FUNC(name_, func_) \
    static parse_info_t * \
    handle_watch_map_value_##name_(parse_info_t *info, yaml_event_t *event, void *data) \
    { \
        watch_t *watch = data; \
        const char *value = get_scalar_value(event); \
        if (value == NULL || watch == NULL) \
            return NULL; \
        watch->name_ = func_(value); \
        info->handler[YAML_SCALAR_EVENT] = handle_watch_map_key; \
        return info; \
    }

#define DECLARE_WATCH_STR_VALUE(name_) \
    DECLARE_WATCH_STR_FUNC(name_, strdup)

#define DECLARE_WATCH_STR_LIST_VALUE(name_) \
    DECLARE_WATCH_STR_FUNC(name_, split_string_whitespace)

DECLARE_WATCH_STR_VALUE(name)
DECLARE_WATCH_STR_VALUE(uid)
DECLARE_WATCH_STR_VALUE(gid)
DECLARE_WATCH_STR_VALUE(dir)
DECLARE_WATCH_STR_VALUE(pid_file)
DECLARE_WATCH_STR_VALUE(log_file)
DECLARE_WATCH_STR_VALUE(error_file)
DECLARE_WATCH_STR_VALUE(http_check)
DECLARE_WATCH_STR_LIST_VALUE(start)
DECLARE_WATCH_STR_LIST_VALUE(stop)
DECLARE_WATCH_STR_FUNC(max_memory, parse_size_unit)
DECLARE_WATCH_STR_FUNC(max_cpu, uatoi)
DECLARE_WATCH_STR_FUNC(stop_timeout, uatoi)
DECLARE_WATCH_STR_FUNC(port_check, uatoi)

#undef DECLARE_WATCH_STR_VALUE
#undef DECLARE_WATCH_STR_LIST_VALUE
#undef DECLARE_WATCH_STR_FUNC

static const char *env_key = NULL;

static parse_info_t *
handle_watch_env_value(parse_info_t *info, yaml_event_t *event, void *data)
{
    const char *env_value = get_scalar_value(event);

    log_debug("Environment variable value: %s", env_value);

    watch_t *watch = data;

    if (watch != NULL && watch->env && env_key)
    {
        hash_add(watch->env, env_key, strdup(env_value));

        /* dispose key */
        free((void *)env_key);
        env_key = NULL;
    }

    info->handler[YAML_SCALAR_EVENT] = handle_watch_env_key;

    return info;
}

static parse_info_t *
handle_watch_env_key(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    const char *new_env_key = get_scalar_value(event);

    log_debug("Environment variable key: %s", new_env_key);

    env_key = strdup(new_env_key);

    info->handler[YAML_SCALAR_EVENT] = handle_watch_env_value;

    return info;
}

static parse_info_t *
handle_watch_env_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    parse_info_t *end_info = handle_mapping_end(info, event, data);

    end_info->handler[YAML_SCALAR_EVENT] = handle_watch_map_key;

    return end_info;
}

static parse_info_t *
handle_watch_env(parse_info_t *info, UNUSED yaml_event_t *event, void *data)
{
    log_debug("handle_watch_env");

    parse_info_t *new_info = parse_info_new_child(info);
    watch_t *watch = data;

    if (!watch->env)
        watch->env = hash_new(free);

    new_info->handler[YAML_SCALAR_EVENT] = handle_watch_env_key;
    new_info->handler[YAML_MAPPING_END_EVENT] = handle_watch_env_end;

    return new_info;
}

static parse_info_t *
handle_watch_http_check_key(parse_info_t *info, yaml_event_t *event, void *data)
{
    const char *key = get_scalar_value(event);

    log_debug("handle_watch_http_check_key: '%s'", key);

    struct watch_info *winfo = data;

    handler_func_t *handler = get_handler_from_map(winfo->map, key);

    if (!handler)
        return info;

    info->handler[YAML_SCALAR_EVENT] = handler[CFG_SCALAR];

    return info;
}

static parse_info_t *
handle_watch_http_check_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    log_debug("handle_watch_http_check_end");

    struct watch_info *winfo = data;

    if (winfo)
    {
        info->data = data = winfo->watch;
        free(winfo);
    }

    parse_info_t *end_info = handle_mapping_end(info, event, data);

    end_info->handler[YAML_SCALAR_EVENT] = handle_watch_map_key;

    return end_info;
}

#define DECLARE_WINFO_FUNC(name_, func_) \
    static parse_info_t * \
    handle_watch_##name_(parse_info_t *info, yaml_event_t *event, void *data) \
    { \
        struct watch_info *winfo = data; \
        const char *value = get_scalar_value(event); \
        if (value == NULL) \
            return NULL; \
        winfo->watch->name_ = func_(value); \
        info->handler[YAML_SCALAR_EVENT] = handle_watch_http_check_key; \
        return info; \
    }

DECLARE_WINFO_FUNC(http_check, strdup)
DECLARE_WINFO_FUNC(http_check_port, uatoi)
DECLARE_WINFO_FUNC(http_check_method, http_method_from_string)

#undef DECLARE_WINFO_FUNC

static struct config_parser_map http_check_map[] =
{
    SCALAR_HANDLER("url", handle_watch_http_check),
    SCALAR_HANDLER("port", handle_watch_http_check_port),
    SCALAR_HANDLER("method", handle_watch_http_check_method),
    { NULL, {0}, NULL }
};

static parse_info_t *
handle_watch_http_check_map(parse_info_t *info, UNUSED yaml_event_t *event, void *data)
{
    log_debug("handle_watch_http_check_map");

    parse_info_t *new_info = parse_info_new_child(info);

    new_info->handler[YAML_SCALAR_EVENT] = handle_watch_http_check_key;
    new_info->handler[YAML_MAPPING_END_EVENT] = handle_watch_http_check_end;

    new_info->data = watch_info_new(data, http_check_map);

    return new_info;
}

static parse_info_t *
handle_watch_string(parse_info_t *info, yaml_event_t *event, void *data)
{
    log_debug("handle_watch_string");

    const char *value = get_scalar_value(event);
    list_t *list = data;

    if (list == NULL || value == NULL)
        return NULL;

    list_add(list, strdup(value));

    return info;
}

#define DECLARE_WATCH_STR_LIST(name_) \
    static parse_info_t * \
    handle_watch_strings_end_##name_(parse_info_t *info, yaml_event_t *event, void *data) \
    { \
        parse_info_t *parent = parser_up(info, event, data); \
        list_t *list = data; \
        watch_t *watch = parent->data; \
        if (list == NULL || watch == NULL) \
            return NULL; \
        watch->name_ = strings_to_null_terminated(list); \
        parent->handler[YAML_SCALAR_EVENT] = handle_watch_map_key; \
        return parent; \
    } \
    static parse_info_t * \
    handle_watch_strings_##name_(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data) \
    { \
        parse_info_t *new_info = parse_info_new_child(info); \
        list_t *list = list_new(NULL); \
        new_info->data = list; \
        new_info->handler[YAML_SCALAR_EVENT] = handle_watch_string; \
        new_info->handler[YAML_SEQUENCE_END_EVENT] = handle_watch_strings_end_##name_; \
        return new_info; \
    }

DECLARE_WATCH_STR_LIST(start)
DECLARE_WATCH_STR_LIST(stop)

#undef DECLARE_WATCH_STR_LIST

static struct config_parser_map watch_value_map[] =
{
    SCALAR_HANDLER("name", handle_watch_map_value_name),
    SCALAR_HANDLER("uid", handle_watch_map_value_uid),
    SCALAR_HANDLER("gid", handle_watch_map_value_gid),
    SCALAR_HANDLER("dir", handle_watch_map_value_dir),
    SCALAR_HANDLER("pid_file", handle_watch_map_value_pid_file),
    SCALAR_HANDLER("log_file", handle_watch_map_value_log_file),
    SCALAR_HANDLER("error_file", handle_watch_map_value_error_file),
    SCALAR_HANDLER("max_memory", handle_watch_map_value_max_memory),
    SCALAR_HANDLER("max_cpu", handle_watch_map_value_max_cpu),
    SCALAR_HANDLER("stop_timeout", handle_watch_map_value_stop_timeout),
    SCALAR_HANDLER("port_check", handle_watch_map_value_port_check),
    MAP_HANDLER("env", handle_watch_env),
    HANDLERS("http_check", handle_watch_map_value_http_check, NULL, handle_watch_http_check_map),
    HANDLERS("start", handle_watch_map_value_start, handle_watch_strings_start, NULL),
    HANDLERS("stop", handle_watch_map_value_stop, handle_watch_strings_stop, NULL),
    { NULL, {0}, NULL }
};

static parse_info_t *
unknown_watch_key(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    /* no op */
    return info;
}

static parse_info_t *
handle_watch_map_key(parse_info_t *info, yaml_event_t *event, void *data)
{
    const char *key;
    watch_t *watch = data;
    handler_func_t *handler = NULL;

    log_debug("handle_watch_map_key");

    key = get_scalar_value(event);

    /* empty key or not a scalar at all */
    if (key == NULL || watch == NULL)
        return NULL;

    handler = get_handler_from_map(watch_value_map, key);

    if (handler == NULL)
    {
        info->handler[YAML_SCALAR_EVENT] = unknown_watch_key;
        info->handler[YAML_MAPPING_START_EVENT] = unknown_watch_key;
        info->handler[YAML_SEQUENCE_START_EVENT] = unknown_watch_key;
    }
    else
    {
        info->handler[YAML_SCALAR_EVENT] = handler[CFG_SCALAR];
        info->handler[YAML_MAPPING_START_EVENT] = handler[CFG_MAP];
        info->handler[YAML_SEQUENCE_START_EVENT] = handler[CFG_LIST];
    }

    return info;
}

static parse_info_t *
handle_watch_map_end(parse_info_t *info, yaml_event_t *event, void *data)
{
    log_debug("handle_watch_map_end");

    parse_info_t *parent = parser_up(info, event, data);

    /* reset data (last watch instance) */
    parent->data = NULL;
    parent->handler[YAML_SCALAR_EVENT] = handle_watch;

    return parent;
}

static parse_info_t *
handle_watch_map(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    parse_info_t *new = NULL;

    log_debug("handle_watch_map");

    new = parse_info_new_child(info);

    new->handler[YAML_SCALAR_EVENT] = handle_watch_map_key;
    new->handler[YAML_MAPPING_END_EVENT] = handle_watch_map_end;

    return new;
}

static parse_info_t *
handle_watch(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle watch");

    const char *name = get_scalar_value(event);

    if (name == NULL)
        return NULL;

    /* does this watch already exist? */
    if (hash_get(info->nyx->watches, name) != NULL)
    {
        log_warn("Watch '%s' already exists", name);
        return info;
    }

    const char *w_name = strdup(name);
    watch_t *watch = watch_new(w_name);

    hash_add(info->nyx->watches, w_name, watch);

    reset_handlers(info);
    info->handler[YAML_MAPPING_START_EVENT] = handle_watch_map;
    info->handler[YAML_MAPPING_END_EVENT] = handle_mapping_end;

    info->data = watch;

    return info;
}

static parse_info_t *
handle_watches(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle watches");

    parse_info_t *new_info = parse_info_new_child(info);

    /* name of the watch */
    new_info->handler[YAML_SCALAR_EVENT] = handle_watch;
    new_info->handler[YAML_MAPPING_END_EVENT] = handle_mapping_end;

    return new_info;
}

#define DECLARE_NYX_FUNC_VALUE(func_, name_) \
    static parse_info_t * \
    handle_nyx_value_##name_(parse_info_t *info, yaml_event_t *event, UNUSED void *data) \
    { \
        nyx_t *nyx = info->nyx; \
        const char *value = get_scalar_value(event); \
        if (value == NULL) \
            return NULL; \
        nyx->options.name_ = func_(value); \
        info->handler[YAML_SCALAR_EVENT] = handle_nyx_key; \
        return info; \
    }

DECLARE_NYX_FUNC_VALUE(uatoi, polling_interval)
DECLARE_NYX_FUNC_VALUE(uatoi, check_interval)
DECLARE_NYX_FUNC_VALUE(uatoi, history_size)
DECLARE_NYX_FUNC_VALUE(uatoi, http_port)
DECLARE_NYX_FUNC_VALUE(strdup, log_file)

#ifdef USE_PLUGINS
DECLARE_NYX_FUNC_VALUE(strdup, plugins)
#endif

#undef DECLARE_NYX_FUNC_VALUE

static struct config_parser_map nyx_value_map[] =
{
    SCALAR_HANDLER("polling_interval", handle_nyx_value_polling_interval),
    SCALAR_HANDLER("check_interval", handle_nyx_value_check_interval),
    SCALAR_HANDLER("history_size", handle_nyx_value_history_size),
    SCALAR_HANDLER("http_port", handle_nyx_value_http_port),
    SCALAR_HANDLER("log_file", handle_nyx_value_log_file),
#ifdef USE_PLUGINS
    SCALAR_HANDLER("plugin_dir", handle_nyx_value_plugins),
#endif
    { NULL, {0}, NULL }
};

static parse_info_t *
unknown_nyx_key(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    info->handler[YAML_SCALAR_EVENT] = handle_nyx_key;

    return info;
}

static parse_info_t *
handle_nyx_key(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    const char *key;
    handler_func_t *handler = NULL;

    log_debug("handle_nyx_key");

    key = get_scalar_value(event);

    /* empty key or not a scalar at all */
    if (key == NULL)
        return NULL;

    handler = get_handler_from_map(nyx_value_map, key);

    if (handler == NULL)
    {
        log_warn("Unknown nyx config key: '%s'", key);

        info->handler[YAML_SCALAR_EVENT] = unknown_nyx_key;
        info->handler[YAML_MAPPING_START_EVENT] = unknown_nyx_key;
        info->handler[YAML_SEQUENCE_START_EVENT] = unknown_nyx_key;
    }
    else
    {
        info->handler[YAML_SCALAR_EVENT] = handler[CFG_SCALAR];
        info->handler[YAML_MAPPING_START_EVENT] = handler[CFG_MAP];
        info->handler[YAML_SEQUENCE_START_EVENT] = handler[CFG_LIST];
    }

    return info;
}

static parse_info_t *
handle_nyx(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_nyx");

    parse_info_t *new_info = parse_info_new_child(info);

    /* handle several (default) config values */
    new_info->handler[YAML_SCALAR_EVENT] = handle_nyx_key;
    new_info->handler[YAML_MAPPING_END_EVENT] = handle_mapping_end;

    return new_info;
}

#ifdef USE_PLUGINS

static const char *plugin_key = NULL;

static parse_info_t *
handle_plugins_key(parse_info_t *info, yaml_event_t *event, UNUSED void *data);

static parse_info_t *
handle_plugins_value(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    const char *value = NULL;

    log_debug("handle_plugins_value");

    value = get_scalar_value(event);

    if (value && plugin_key)
    {
        hash_add(info->nyx->options.plugin_config,
                plugin_key, strdup(value));

        /* dispose key */
        free((void *)plugin_key);
        plugin_key = NULL;
    }

    info->handler[YAML_SCALAR_EVENT] = handle_plugins_key;

    return info;
}

static parse_info_t *
handle_plugins_key(parse_info_t *info, yaml_event_t *event, UNUSED void *data)
{
    const char *key;

    log_debug("handle_plugins_key");

    key = get_scalar_value(event);

    if (key == NULL)
        return NULL;

    plugin_key = strdup(key);

    info->handler[YAML_SCALAR_EVENT] = handle_plugins_value;

    return info;
}

static parse_info_t *
handle_plugins(parse_info_t *info, UNUSED yaml_event_t *event, UNUSED void *data)
{
    log_debug("handle_plugins");

    if (info->nyx->options.plugin_config == NULL)
        info->nyx->options.plugin_config = hash_new(free);

    parse_info_t *new_info = parse_info_new_child(info);

    new_info->handler[YAML_SCALAR_EVENT] = handle_plugins_key;
    new_info->handler[YAML_MAPPING_END_EVENT] = handle_mapping_end;

    return new_info;
}

#endif /* USE_PLUGINS */

static struct config_parser_map root_map[] =
{
    MAP_HANDLER("watches", handle_watches),
    MAP_HANDLER("nyx", handle_nyx),
#ifdef USE_PLUGINS
    MAP_HANDLER("plugins", handle_plugins),
#endif
    { NULL, {0}, NULL }
};

#undef SCALAR_HANDLER
#undef MAP_HANDLER
#undef HANDLERS

parse_info_t *
parse_info_new(nyx_t *nyx)
{
    parse_info_t *info = xcalloc(1, sizeof(parse_info_t));

    info->nyx = nyx;
    info->handler[YAML_STREAM_START_EVENT] = handle_stream;
    info->data = &root_map;

    return info;
}

parse_info_t *
parse_info_new_child(parse_info_t *parent)
{
    parse_info_t *info = xcalloc(1, sizeof(parse_info_t));

    info->nyx = parent->nyx;
    info->parent = parent;

    /* migrate data to child if given */
    info->data = parent->data;

    return info;
}

static void
parse_info_destroy(parse_info_t *info)
{
    parse_info_t *next = info;

    while (next)
    {
        next = info->parent;

        free(info);
        info = next;
    }
}

static void
unexpected_element(yaml_event_t *event)
{
    const char *type = yaml_event_names[event->type];

    if (event->start_mark.column > 0)
    {
        log_warn("Unexpected element '%s' [line %zu, col %zu]",
                type,
                event->start_mark.line,
                event->start_mark.column);
    }
    else
    {
        log_warn("Unexpected element '%s' [line %zu]",
                type,
                event->start_mark.line);
    }
}

static void
dump_watch(void *data)
{
    watch_dump((watch_t *) data);
}

static int
invalid_watch(void *watch)
{
    return !watch_validate((watch_t *)watch);
}

int
parse_config(nyx_t *nyx)
{
    int success = 1;
    FILE *cfg = NULL;
    handler_func_t handler = NULL;
    const char *config_file = nyx->options.config_file;

    if (config_file == NULL)
        return 0;

    yaml_parser_t parser;
    yaml_event_t event;

    /* read input file */
    cfg = fopen(config_file, "r");
    if (cfg == NULL)
    {
        log_perror("nyx: fopen");
        return 0;
    }

    /* initialize yaml parser */
    if (!yaml_parser_initialize(&parser))
    {
        log_warn("Failed to parse config file %s", config_file);
        fclose(cfg);
        return 0;
    }

    parse_info_t *info = parse_info_new(nyx);
    parse_info_t *new_info = NULL;

    yaml_parser_set_input_file(&parser, cfg);

    /* start parsing */
    do
    {
        if (!yaml_parser_parse(&parser, &event))
        {
           log_error("Parser error: %d", parser.error);
           success = 0;
           break;
        }

        handler = info->handler[event.type];
        if (handler != NULL)
        {
            new_info = handler(info, &event, info->data);
            if (new_info == NULL)
            {
                log_warn("Invalid configuration '%s'", config_file);
                success = 0;
                break;
            }

            info = new_info;
        }
        else
            unexpected_element(&event);

        if (event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);
    }
    while (event.type != YAML_STREAM_END_EVENT);

    /* cleanup */
    yaml_parser_delete(&parser);

    if (env_key)
    {
        free((void *)env_key);
        env_key = NULL;
    }

#ifdef USE_PLUGINS
    if (plugin_key)
    {
        free((void *)plugin_key);
        plugin_key = NULL;
    }
#endif

    parse_info_destroy(info);
    fclose(cfg);

    /* validate watches */
    int filtered = 0;
    if ((filtered = hash_filter(nyx->watches, invalid_watch)) > 0)
    {
        log_warn("Found %d invalid watches", filtered);
    }

    int valid_watches = hash_count(nyx->watches);
    if (valid_watches < 1)
    {
        log_error("No valid watches configured");
        return 0;
    }

    if (success)
    {
        log_info("Found %d watch definitions", valid_watches);

        hash_foreach(nyx->watches, dump_watch);
    }

    return success;
}

/* vim: set et sw=4 sts=4 tw=80: */
