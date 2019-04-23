#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sandbox.h"
#include "ssc.h"

const char *argp_program_version = "0.1.0";
const char *argp_program_bug_address = "<i@sst.st>";
static char doc[] = "SSX Online Judge Core - C version";
static char args_doc[] = "[BINARY] [ARGS]...";
static struct argp_option options[] = {
    {"time-limit", 't', "TIME_LIMIT"},
    {"memory-limit", 'm', "MEMORY_LIMIT"},
    {0},
};

struct arguments {
    int time_limit;
    int memory_limit;
    char *bin;
    char **args;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 't':
            arguments->time_limit = atoi(arg);
            break;
        case 'm':
            arguments->memory_limit = atoi(arg);
            break;
        case ARGP_KEY_NO_ARGS:
            argp_usage(state);
        case ARGP_KEY_ARG:
            arguments->bin = arg;
            arguments->args = &state->argv[state->next];
            state->next = state->argc;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc };

int main(int argc, char *argv[]) {
    struct arguments arguments;
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    pid_t pid;
    if ((pid = fork()) < 0) {
        return SCE_FORK;
    } else if (pid == 0) {
        if (ssx_seccomp_load_regular("./t") != 0) {
            return SCE_LDSCMP;
        }
        char* argv[] = { "./t", 0 };
        char* envp[] = { 0 };
        execve("./t", argv, envp);
    } else {
        int status;
        struct rusage resource_usage;
        if (wait4(pid, &status, WSTOPPED, &resource_usage) == -1) {
            kill(pid, SIGKILL);
        }
        printf("[%d]\n", status);
    }

    return 0;
}
