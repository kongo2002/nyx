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

#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

bool
is_directory(const char *path);

bool
dir_writable(const char *directory);

bool
file_exists(const char *file);

bool
dir_exists(const char *directory);

bool
create_if_not_exists(const char *file);

const char *
parent_dir(const char *directory);

const char *
local_socket_path(const char *local_dir);

const char *
find_local_socket_path(const char *start_dir);

const char *
determine_socket_path(const char *local_dir, const char *socket_file, bool local_only);

const char *
determine_pid_dir(void);

const char *
determine_local_pid_dir(const char *local_dir);

FILE *
open_pid_file(const char *pid_dir, const char *name, const char *mode);

bool
remove_pid_file(const char *pid_dir, const char *name);

const char *
get_current_dir(void);

const char *
get_homedir(void);

bool
get_user(const char *name, uid_t *uid, gid_t *gid);

bool
get_group(const char *name, gid_t *gid);

/* vim: set et sw=4 sts=4 tw=80: */
