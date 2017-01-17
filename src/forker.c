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
#include "forker.h"
#include "fs.h"
#include "log.h"
#include "process.h"
#include "watch.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static watch_t *
find_watch(nyx_t *nyx, int32_t id)
{
    if (nyx->watches == NULL)
        return NULL;

    const char *key = NULL;
    void *data = NULL;

    hash_iter_t *iter = hash_iter_start(nyx->watches);

    while (hash_iter(iter, &key, &data))
    {
        watch_t *watch = data;

        if (watch && watch->id == id)
        {
            free(iter);
            return watch;
        }
    }

    free(iter);
    return NULL;
}

static void
set_environment(const watch_t *watch)
{
    const char *key = NULL;
    void *data = NULL;

    if (watch->env == NULL || hash_count(watch->env) < 1)
        return;

    hash_iter_t *iter = hash_iter_start(watch->env);

    while (hash_iter(iter, &key, &data))
    {
        char *value = data;

        setenv(key, value, 1);
    }

    free(iter);
}

static void
close_fds(pid_t pid)
{
    char path[256] = {0};

    /* first we try to search in /proc/{pid}/fd */
    snprintf(path, LEN(path)-1, "/proc/%d/fd", pid);

    DIR *dir = opendir(path);
    if (dir)
    {
        int32_t dir_fd = dirfd(dir);

        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL)
        {
            int32_t fd = atoi(entry->d_name);

            if (fd >= 3 && fd != dir_fd)
                close(fd);
        }

        closedir(dir);
        return;
    }

    /* otherwise we will close all file descriptors up
     * to the maximum descriptor index */
    int32_t max;
    if ((max = getdtablesize()) == -1)
        max = 256;

    for (int32_t fd = 3 /* stderr + 1 */; fd < max; fd++)
        close(fd);
}

static bool
write_pipe(int32_t fd, int32_t value)
{
    FILE *stream = fdopen(fd, "w");

    if (stream != NULL)
    {
        fprintf(stream, "%d\n", value);

        fclose(stream);
        return true;
    }

    return false;
}

static int32_t
read_pipe(int32_t fd)
{
    int32_t value = 0;
    FILE *stream = fdopen(fd, "r");

    if (stream != NULL)
    {
        if (fscanf(stream, "%d", &value) != 1)
            value = 0;

        fclose(stream);
    }

    return value;
}

static void
spawn_exec(watch_t *watch, bool start)
{
    uid_t uid = 0;
    gid_t gid = 0;

    const char **args = start ? watch->start : watch->stop;
    const char *executable = *args;
    const char *dir = dir_exists(watch->dir) ? watch->dir : "/";

    /* determine user and group */
    if (watch->uid)
        get_user(watch->uid, &uid, &gid);

    if (watch->gid)
        get_group(watch->gid, &gid);

    /* TODO: configurable mask */
    umask(0);

    /* create session */
    setsid();

    /* set user/group */
    if (gid)
    {
        gid_t groups[] = { gid };

        setgroups(1, groups);

        if (setgid(gid) == -1)
            log_perror("nyx: setgid");
    }

    if (uid && gid)
        initgroups(watch->uid, gid);

    if (uid)
    {
        /* in case the uid was modified we adjust the $USER and $HOME
         * environment variables appropriately */
        if (setuid(uid) != -1)
        {
            if (!watch->env)
                watch->env = hash_new(free);

            if (!hash_get(watch->env, "USER"))
            {
                hash_add(watch->env, "USER", strdup(watch->uid));
            }

            if (!hash_get(watch->env, "HOME"))
            {
                struct passwd *pw = getpwuid(uid);

                if (pw && pw->pw_dir)
                    hash_add(watch->env, "HOME", strdup(pw->pw_dir));
            }
        }
    }

    if (chdir(dir) == -1)
        log_critical_perror("nyx: chdir");

    /* stdin */
    close(STDIN_FILENO);

    if (open("/dev/null", O_RDONLY) == -1)
    {
        fprintf(stderr, "Failed to open /dev/null");
        exit(EXIT_FAILURE);
    };

    /* stdout */
    close(STDOUT_FILENO);

    if (start && watch->log_file)
    {
        if (open(watch->log_file,
                    O_RDWR | O_APPEND | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1)
        {
            fprintf(stderr, "Failed to open log file '%s'",
                    watch->log_file);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        if (open("/dev/null", O_WRONLY) == -1)
        {
            fprintf(stderr, "Failed to open /dev/null");
            exit(EXIT_FAILURE);
        }
    }

    /* stderr */
    close(STDERR_FILENO);

    if (start && watch->error_file)
    {
        if (open(watch->error_file,
                    O_RDWR | O_APPEND | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1)
        {
            fprintf(stdout, "Failed to open error file '%s'",
                    watch->error_file);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        if (open("/dev/null", O_RDWR) == -1)
        {
            fprintf(stdout, "Failed to open /dev/null");
            exit(EXIT_FAILURE);
        }
    }

    set_environment(watch);
    close_fds(getpid());

    /* on success this call won't return */
    execvp(executable, (char * const *)args);

    if (errno == ENOENT)
        exit(EXIT_SUCCESS);

    log_critical_perror("nyx: execvp %s", executable);
}

static pid_t
spawn_stop(watch_t *watch)
{
    pid_t pid = fork();

    if (pid == -1)
        log_critical_perror("nyx: fork");

    if (pid == 0)
    {
        spawn_exec(watch, false);
    }

    return pid;
}

static pid_t
spawn_start(nyx_t *nyx, watch_t *watch)
{
    int32_t pipes[2] = {0};
    bool double_fork = !nyx->is_init;

    /* in case of a 'double-fork' we need some way to retrieve the
     * resulting process' pid */
    if (double_fork)
    {
        if (pipe(pipes) == -1)
            log_critical_perror("nyx: pipe");
    }

    pid_t pid = fork();
    pid_t outer_pid = pid;

    /* fork failed */
    if (pid == -1)
        log_critical_perror("nyx: fork");

    /* child process */
    if (pid == 0)
    {
        /* in 'init mode' we have to fork only once */
        if (!double_fork)
        {
            /* this call won't return */
            spawn_exec(watch, true);
        }
        /* otherwise we want to 'double fork' */
        else
        {
            pid_t inner_pid = fork();

            if (inner_pid == -1)
                log_critical_perror("nyx: fork");

            if (inner_pid == 0)
            {
                /* this call won't return */
                spawn_exec(watch, true);
            }

            /* close the read end before */
            close(pipes[0]);

            /* now we write the child pid into the pipe */
            write_pipe(pipes[1], inner_pid);

            exit(EXIT_SUCCESS);
        }
    }

    /* in case of a 'double-fork' we have to read the actual
     * process' pid from the read end of the pipe */
    if (double_fork)
    {
        /* close the write end before */
        close(pipes[1]);

        pid = read_pipe(pipes[0]);

        /* wait for the intermediate forked process
         * to terminate */
        waitpid(outer_pid, NULL, 0);
    }

    return pid;
}

static void
forker(nyx_t *nyx, int32_t pipe)
{
    fork_info_t info = {0};

    while (read(pipe, &info, sizeof(fork_info_t)) != 0)
    {
        log_debug("forker: received watch id %d", info.id);

        watch_t *watch = find_watch(nyx, info.id);

        if (watch == NULL)
        {
            log_warn("forker: no watch with id %d found!", info.id);
            continue;
        }

        pid_t pid = (info.start)
            ? spawn_start(nyx, watch)
            : spawn_stop(watch);

        write_pid(pid, watch->name, nyx);
    }

    close(pipe);

    log_debug("forker: terminated");
}

static fork_info_t *
forker_new(int32_t id, bool start)
{
    fork_info_t *info = xcalloc1(sizeof(fork_info_t));

    info->id = id;
    info->start = start;

    return info;
}

fork_info_t *
forker_stop(int32_t idx)
{
    return forker_new(idx, false);
}

fork_info_t *
forker_start(int32_t idx)
{
    return forker_new(idx, true);
}

int32_t
forker_init(nyx_t *nyx)
{
    int32_t pipes[2] = {0};

    /* open pipes -> bail out if failed */
    if (pipe(pipes) == -1)
        return 0;

    /* here we are still in the main nyx thread
     * we will fork now so both threads have access to both the read
     * and write side of the pipes */

    pid_t pid = fork();

    /* fork failed */
    if (pid == -1)
        return 0;

    /* here we are in the child/forker thread */
    if (pid == 0)
    {
        /* close the write end of the pipes first */
        close(pipes[1]);

        /* ignore SIGINT - we are terminated by the main thread */
        signal(SIGINT, SIG_IGN);

        /* enter the real fork processing logic now */
        forker(nyx, pipes[0]);
        exit(EXIT_SUCCESS);
    }

    /* parent/main thread here:
     * close the read end of the pipes */
    close(pipes[0]);

    /* return the write pipe descriptor */
    return pipes[1];
}

/* vim: set et sw=4 sts=4 tw=80: */
