#include "sandbox.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "sce.h"

const int rules_default[] = {
    SCMP_SYS(mkdir),
    INT_MAX,
};

int ssc_seccomp_init(scmp_filter_ctx ctx, const int *rules, int whitelist) {
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

int ssc_seccomp_add(scmp_filter_ctx ctx, const int *rules, int action) {
    for (int i = 0; rules[i] != INT_MAX; ++i) {
        if (seccomp_rule_add(ctx, action, rules[i], 0) != 0) {
            seccomp_release(ctx);
            return SCE_LDSCMP;
        }
    }
    return 0;
}

int ssc_seccomp_load_manually(char *path, int argc, char **argv) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 1,
                         SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)(path))) != 0) {
        seccomp_release(ctx);
        return SCE_LDSCMP;
    }
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) break;
        if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 1,
                             SCMP_A0(SCMP_CMP_NE, (scmp_datum_t)(argv[i]))) !=
            0) {
            seccomp_release(ctx);
            return SCE_LDSCMP;
        }
    }

    /* Load */
    if (ssc_seccomp_init(ctx, rules_default, 0)) {
        seccomp_release(ctx);
        return SCE_LDSCMP;
    }

    seccomp_release(ctx);
    return 0;
}

void kill_childprocess() {
    extern pid_t pid;
    kill(pid, SIGKILL);
}