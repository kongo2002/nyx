#include "fs.h"
#include "process.h"

pid_t
determine_pid(const char *name, nyx_t *nyx)
{
    int matched = 0;
    pid_t pid = 0;
    FILE *file = NULL;

    if (name == NULL)
        return 0;

    if ((file = get_pid_file(nyx->pid_dir, name, "r")) != NULL)
    {
        matched = fscanf(file, "%ud", &pid);
        fclose(file);
    }

    if (matched == 1)
        return pid;

    return 0;
}

int
write_pid(pid_t pid, const char *name, nyx_t *nyx)
{
    int written = 0;
    FILE *file = NULL;

    if (name == NULL)
        return 0;

    if ((file = get_pid_file(nyx->pid_dir, name, "w")) != NULL)
    {
        written = fprintf(file, "%ud", pid);
        fclose(file);
    }

    return written > 0;
}

/* vim: set et sw=4 sts=4 tw=80: */
