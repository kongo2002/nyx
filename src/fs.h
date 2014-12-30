#ifndef __NYX_FS_H__
#define __NYX_FS_H__

#include <stdio.h>

int
dir_exists(const char *directory);

int
mkdir_p(const char *directory);

FILE *
get_pid_file(const char *pid_dir, const char *name, const char *mode);

const char *
get_homedir(void);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
