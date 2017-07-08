/* Copyright 2014-2017 Gregor Uhlenheuer
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

#include "def.h"
#include "fs.h"
#include "log.h"

#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *
get_homedir(void)
{
    const char *homedir;

    /* try $HOME first */
    if ((homedir = getenv("HOME")) == NULL)
    {
        uid_t uid = getuid();
        struct passwd *pwd = getpwuid(uid);

        if (pwd == NULL)
            return NULL;

        return pwd->pw_dir;
    }

    return homedir;
}

bool
get_user(const char *name, uid_t *uid, gid_t *gid)
{
    struct passwd *pw = getpwnam(name);

    if (pw == NULL)
        return false;

    *uid = pw->pw_uid;
    *gid = pw->pw_gid;

    return true;
}

bool
get_group(const char *name, gid_t *gid)
{
    struct group *grp = getgrnam(name);

    if (grp == NULL)
        return false;

    *gid = grp->gr_gid;

    return true;
}

static const char *
prepare_dir(const char *directory)
{
    /* replace ~ if necessary */
    if (*directory == '~')
    {
        static char buffer[512] = {0};

        /* clear buffer from previous runs */
        memset(buffer, 0, sizeof(buffer));

        snprintf(buffer, sizeof(buffer), "%s%s",
                get_homedir(),
                directory + 1);

        return buffer;
    }

    return directory;
}

static const char *pid_dir_defaults[] =
{
    "/var/run/nyx",
    "~/.nyx/pid",
    "/tmp/nyx/pid",
    NULL
};

static bool
mkdir_p(const char *directory)
{
    char buffer[512] = {0};

    if (directory == NULL || *directory == '\0')
        return false;

    snprintf(buffer, sizeof(buffer), "%s", directory);
    size_t length = strlen(buffer);
    size_t end = length - 1;

    /* remove trailing slash if necessary */
    if (buffer[end] == '/')
        buffer[end] = '\0';

    for (char *p = buffer + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';

            if (mkdir(buffer, S_IRWXU) == -1 && errno != EEXIST)
                return false;
            *p = '/';
        }
    }

    if (mkdir(buffer, S_IRWXU) == -1 && errno != EEXIST)
        return false;

    return true;
}

const char *
determine_pid_dir(void)
{
    const char **dir = pid_dir_defaults;

    while (*dir)
    {
        const char *prepared = strdup(prepare_dir(*dir));

        if (prepared == NULL)
        {
            log_critical_perror("nyx: strdup");
        }

        /* check if the directory exists or can be created */
        if (mkdir_p(prepared))
        {
            /* now we should be able to access it as well */
            int32_t result = access(prepared, W_OK);

            if (result == 0)
            {
                log_debug("Using '%s' as nyx PID directory", prepared);
                return prepared;
            }
        }

        free((void *)prepared);

        dir++;
    }

    log_error("Failed to determine a PID directory for nyx");

    return NULL;
}

static char *
get_pid_file(const char *pid_dir, const char *name)
{
    char *buffer = xcalloc(512, sizeof(char));

    snprintf(buffer, 511, "%s/%s", pid_dir, name);

    return buffer;
}

FILE *
open_pid_file(const char *pid_dir, const char *name, const char *mode)
{
    if (pid_dir == NULL)
        return NULL;

    char *location = get_pid_file(pid_dir, name);
    FILE *pid_file = fopen(location, mode);

    free(location);
    return pid_file;
}

bool
remove_pid_file(const char *pid_dir, const char *name)
{
    if (pid_dir == NULL)
        return false;

    char *location = get_pid_file(pid_dir, name);
    bool success = remove(location) == 0;

    free(location);
    return success;
}

bool
dir_exists(const char *directory)
{
    if (directory == NULL || *directory == '\0')
        return false;

    DIR *dir = opendir(prepare_dir(directory));

    if (dir != NULL)
    {
        closedir(dir);
        return true;
    }

    /* no need to check errno */

    return false;
}

bool
is_directory(const char *path)
{
    bool is_dir = false;
    char *copy = strdup(prepare_dir(path));

    if (copy == NULL)
        log_critical_perror("nyx: strdup");

    struct stat path_stat;
    if (stat(copy, &path_stat) == 0)
    {
        is_dir = S_ISDIR(path_stat.st_mode);
    }

    free(copy);
    return is_dir;
}

bool
dir_writable(const char *directory)
{
    bool writable = false;
    char *copy = strdup(prepare_dir(directory));

    if (copy == NULL)
        log_critical_perror("nyx: strdup");

    const char *dir = dirname(copy);

    if (dir_exists(dir))
    {
        int32_t error = access(dir, W_OK);

        if (error == -1)
            log_perror("nyx: access");

        if (error == 0)
            writable = true;
    }

    free(copy);

    return writable;
}

/* vim: set et sw=4 sts=4 tw=80: */
