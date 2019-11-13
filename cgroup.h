#ifndef CGROUP_H
#define CGROUP_H

#include <sys/types.h>

#define CGFS_BASE "/sys/fs/cgroup"
#define CGFS_NAME "sscts"

int init_cgroup(const char *group_name);
int setup_cgroup(const char *group_name, char *sub_group,unsigned t);
int add_pid_to_cg(pid_t pid, const char *sub_group);
int get_cg_result(const char *name, const char *sub_group, size_t *result);
int cleanup_cg(const char *sub_group);
int force_empty_mem(const char *sub_group);
int flush(const char *sub_group, const char *name);

#endif  // CGROUP_H
