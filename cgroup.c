#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cgroup.h"
#include "sce.h"

static int echo(const char *out, const char *file) {
    if (!out) return SCE_ECHO;
    size_t len = strlen(out);
    if (!len) return SCE_ECHO;

    int fd = open(file, O_WRONLY);
    if (fd == -1) {
        return SCE_ECHO;
    }
    ssize_t r = write(fd, out, len);
    if (r == -1) {
        return SCE_ECHO;
    }
    if (r != len) {
        return SCE_ECHO;
    }
    int ret = close(fd);
    if (ret == -1) {
        return SCE_ECHO;
    }
    return 0;
}

int init_cgroup(const char *group_name) {
    extern int is_root;
    if (!is_root) return SCE_PERM;
    int ret;
    mode_t perm = 0755;
    char name[512] = {0};
    sprintf(name, "%s/%s/%s", CGFS_BASE, group_name, CGFS_NAME);
    if ((ret = mkdir(name, perm))) {
        return SCE_PERM;
    }
    return 0;
}

int setup_cgroup(const char *group_name, char *sub_group) {
    sprintf(sub_group, "%s/%s/%s/%u", CGFS_BASE, group_name, CGFS_NAME,
            getpid());
    int ret = mkdir(sub_group, 0755);
    if (ret) {
        return SCE_CG;
    }
    // no checking memory.max_usage_in_bytes equals zero here
    // underlying risk
    return 0;
}

int add_pid_to_cg(pid_t pid, const char *sub_group) {
    char file[512] = {0};
    sprintf(file, "%s/tasks", sub_group);
    char pid_str[32] = {0};
    sprintf(pid_str, "%zd", (ssize_t)pid);
    int ret = echo(pid_str, file);
    if (ret) return SCE_CGAT;
    return 0;
}

static int cat(const char *file, char *out, size_t len) {
    if (!out || !len) return -2;
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        return SCE_CGNOENT;
    }
    ssize_t r = read(fd, out, len - 1);
    if (r == -1) {
        return SCE_CGRST;
    }
    out[r] = 0;
    if (close(fd)) {
        return SCE_CGRST;
    }
    return 0;
}

int get_cg_result(const char *name, const char *sub_group, size_t *result) {
    char file[512] = {0};
    sprintf(file, "%s/%s", sub_group, name);
    char out[32] = {0};
    int ret = cat(file, out, 32);
    if (ret) {
        return SCE_CGRST;
    }
    *result = strtoul(out, 0, 10);
    return 0;
}

int cleanup_cg(const char *sub_group) {
    if (rmdir(sub_group)) {
        return SCE_CGCU;
    }
    return 0;
}

int force_empty_mem(const char *sub_group) {
    char file[256] = {0};
    snprintf(file, 256, "%s/memory.force_empty", sub_group);
    int ret = echo("0", file);
    if (ret) return SCE_CGCU;
    return 0;
}
