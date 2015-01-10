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

#ifndef __NYX_FS_H__
#define __NYX_FS_H__

#include <stdio.h>
#include <sys/types.h>

int
dir_writable(const char *directory);

int
dir_exists(const char *directory);

int
mkdir_p(const char *directory);

const char *
determine_pid_dir(void);

const char *
get_pid_file(const char *pid_dir, const char *name);

FILE *
open_pid_file(const char *pid_dir, const char *name, const char *mode);

int
remove_pid_file(const char *pid_dir, const char *name);

const char *
get_homedir(void);

int
get_user(const char *name, uid_t *uid, gid_t *gid);

int
get_group(const char *name, gid_t *gid);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
