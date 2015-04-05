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

#include "plugins.h"

#include <stdio.h>
#include <sys/types.h>


static void
handle_callback(const char *name, int state, pid_t pid)
{
    printf("test plugin: got event %d of watch '%s' [%d]\n", state, name, pid);
}

int
plugin_init(plugin_manager_t *manager)
{
    plugin_register_state_callback(manager, "test", handle_callback);

    return 1;
}


/* vim: set et sw=4 sts=4 tw=80: */
