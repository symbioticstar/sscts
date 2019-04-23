#ifndef SANDBOX_H
#define SANDBOX_H

extern const int rules_c_cpp[];
extern const int rules_regular[];
int ssx_seccomp_init(int *rules, int whitelist);
int ssx_seccomp_load_c_cpp(char *path);
int ssx_seccomp_load_regular(char *path)

/* code */
#endif //SANDBOX_H

