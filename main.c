#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sandbox.h"
#include "result.h"
#include "ssc.h"

const char *argp_program_version = "0.1.0";
const char *argp_program_bug_address = "<i@sst.st>";
static char doc[] = "SSX Online Judge Core - C version";
static char args_doc[] = "[BINARY] [ARGS]...";
static struct argp_option options[] = {
    {"time-limit", 't', "TIME_LIMIT"},
    {"memory-limit", 'm', "MEMORY_LIMIT"},
    {"c-cpp", 'c', 0},
    {"regular", 'r', 0},
    {0},
};

struct arguments {
    int time_limit;
    int memory_limit;
    char *bin;
    char **args;
    char strategy;
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
        case 'r':
            arguments->strategy = 'r';
            break;
        case 'c':
            arguments->strategy = 'c';
            break;
        case ARGP_KEY_NO_ARGS:
            argp_usage(state);
        case ARGP_KEY_ARG:
            arguments->bin = arg;
            arguments->args = &state->argv[state->next - 1];
            state->next = state->argc;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc };

int main(int argc, char *argv[]) {
    /* Init */
    struct arguments arguments;
    arguments.strategy = 'c';

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    pid_t pid;
    if ((pid = fork()) < 0) {
        return SCE_FORK;
    } else if (pid == 0) {
        switch (arguments.strategy) {
            case 'r':
                if (ssc_seccomp_load_regular(arguments.bin) != 0) {
                    return SCE_LDSCMP;
                }
                break;
            case 'c':
                if (ssc_seccomp_load_c_cpp(arguments.bin) != 0) {
                    return SCE_LDSCMP;
                }
                break;
        }
        char* envp[] = { 0 };

        execve(arguments.bin, arguments.args, envp);
    } else {
        int status;
        struct rusage rusage;
        if (wait4(pid, &status, WSTOPPED, &rusage) == -1) {
            kill(pid, SIGKILL);
        }
        struct ssc_result result;
        ssc_result_parse_rusage(&result, &rusage);
        printf("Status: %d, Time: %ldms, Memory: %ldKB\n", status, result.cpu_time, result.memory);
    }

    return 0;
}
