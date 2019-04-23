#ifndef SANDBOX_H
#define SANDBOX_H

#include <seccomp.h>

extern const int rules_c_cpp[];
extern const int rules_regular[];
int ssx_seccomp_init(scmp_filter_ctx ctx, const int *rules, int whitelist, char *path);
int ssx_seccomp_add(scmp_filter_ctx ctx, const int* rules, int action);
int ssx_seccomp_load_c_cpp(char *path);
int ssx_seccomp_load_regular(char *path);

/* code */
#endif //SANDBOX_H

