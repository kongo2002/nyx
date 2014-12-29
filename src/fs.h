#ifndef __NYX_FS_H__
#define __NYX_FS_H__

int
dir_exists(const char *directory);

int
mkdir_p(const char *directory);

const char *
get_homedir(void);

#endif

/* vim: set et sw=4 sts=4 tw=80: */
