#ifndef SANDBOX_H
#define SANDBOX_H

#include <seccomp.h>

extern const int rules_c_cpp[];
extern const int rules_python[];
int ssc_seccomp_init(scmp_filter_ctx ctx, const int *rules, int whitelist);
int ssc_seccomp_add(scmp_filter_ctx ctx, const int* rules, int action);
int ssc_seccomp_load_c_cpp(char *path);
int ssc_seccomp_load_python(char *path);
int ssc_seccomp_load_manually(char *path, int argc, char **argv);
void kill_childprocess();

/* code */
#endif //SANDBOX_H

