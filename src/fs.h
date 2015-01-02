#ifndef __NYX_FS_H__
#define __NYX_FS_H__

#include <stdio.h>
#include <sys/types.h>

int
dir_exists(const char *directory);

int
mkdir_p(const char *directory);

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
