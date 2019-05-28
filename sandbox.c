#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include "sandbox.h"
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
    SCMP_SYS(uname),
    SCMP_SYS(readlink),
    SCMP_SYS(exit_group),
    INT_MAX,
};

const int rules_regular[] = {
    // SCMP_SYS(socket),
    SCMP_SYS(clone),
    SCMP_SYS(fork),
    SCMP_SYS(vfork),
    SCMP_SYS(kill),
    INT_MAX,
};

int ssc_seccomp_init(scmp_filter_ctx ctx, const int *rules, int whitelist, char *path) {

    /* Create Filter */
    int action;
    if (whitelist) {
        action = SCMP_ACT_ALLOW;
    } else {
        action = SCMP_ACT_KILL;
    }

    /* Add rules */
    if (ssc_seccomp_add(ctx, rules, action)) {
        return SCE_LDSCMP;
    }

    /* Load Filter */
    if (seccomp_load(ctx) != 0) {
        return SCE_LDSCMP;
    }

    return 0;
}

int ssc_seccomp_add(scmp_filter_ctx ctx, const int* rules, int action) {
    for (int i = 0; rules[i] != INT_MAX; ++i) {
        if (seccomp_rule_add(ctx, action, rules[i], 0) != 0) {
            seccomp_release(ctx);
            return SCE_LDSCMP;
        };
    }
    return 0;
}

int ssc_seccomp_load_c_cpp(char *path) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) return SCE_LDSCMP;

    /* Add Extra Rules*/
    if (path) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)(path))) != 0) {
            seccomp_release(ctx);
            return SCE_LDSCMP;
        }
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0)) != 0) {
        seccomp_release(ctx);
        return SCE_LDSCMP;
    }

    /* Load */
    if (ssc_seccomp_init(ctx, rules_c_cpp, 1, path)) {
        return SCE_LDSCMP;
    }

    seccomp_release(ctx);
    return 0;
}

int ssc_seccomp_load_regular(char *path) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return SCE_LDSCMP;

    /* Add Extra Rules*/
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)(path))) != 0) {
        return SCE_LDSCMP;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) != 0) {
        return SCE_LDSCMP;
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) != 0) {
        return SCE_LDSCMP;
    }

    /* Load */
    if (ssc_seccomp_init(ctx, rules_regular, 0, path)) {
        return SCE_LDSCMP;
    }

    seccomp_release(ctx);
    return 0;
}

void kill_childprocess() {
    extern pid_t pid;
    kill(pid, SIGKILL);
}