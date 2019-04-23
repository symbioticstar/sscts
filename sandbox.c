#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <fcntl.h>
#include "ssc.h"


const int rules_c_cpp[] = {
    SCMP_SYS(mprotect),
    SCMP_SYS(mmap),
    SCMP_SYS(openat),
    SCMP_SYS(access),
    SCMP_SYS(read),
    SCMP_SYS(close),
    SCMP_SYS(fstat),
    SCMP_SYS(munmap),
    SCMP_SYS(brk),
    SCMP_SYS(arch_prctl),
    SCMP_SYS(execve),
    SCMP_SYS(write),
    SCMP_SYS(lseek),
    SCMP_SYS(exit_group),
    INT_MAX,
};

const int rules_regular[] = {
    SCMP_SYS(socket),
    SCMP_SYS(clone),
    SCMP_SYS(fork),
    SCMP_SYS(vfork),
    SCMP_SYS(kill)
};

int ssx_seccomp_init(const int *rules, int whitelist, char *path) {
    /* Create Filter */
    scmp_filter_ctx ctx = NULL;
    int action;
    if (whitelist) {
        ctx = seccomp_init(SCMP_ACT_KILL);
        action = SCMP_ACT_ALLOW;
    } else {
        ctx = seccomp_init(SCMP_ACT_ALLOW);
        action = SCMP_ACT_KILL;
    }
    if (ctx == NULL) return SCE_LDSCMP;
    /* Add rules */
    for (int i = 0; rules[i] != INT_MAX; ++i) {
        if (seccomp_rule_add(ctx, action, rules[i], 0) != 0) {
            seccomp_release(ctx);
            return SCE_LDSCMP;
        };
    }
    /* Add Extra Rules*/
    if (path) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)(path))) != 0) {
            seccomp_release(ctx);
            return SCE_LDSCMP;
        }
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR)) != 0) {
        seccomp_release(ctx);
        return SCE_LDSCMP;
    }
    /* Load Filter */
    if (seccomp_load(ctx) != 0) {
        seccomp_release(ctx);
        return SCE_LDSCMP;
    }
    seccomp_release(ctx);
    return 0;
}

inline int ssx_seccomp_load_c_cpp(char *path) {
    return ssx_seccomp_init(rules_c_cpp, 1, path);
}

inline int ssx_seccomp_load_regular(char *path) {
    return ssx_seccomp_init(rules_regular, 0, path);
}