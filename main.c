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

const char *argp_program_version = "0.2.0";
const char *argp_program_bug_address = "<i@sst.st>";
static char doc[] = "SSX Online Judge Core - C version";
static char args_doc[] = "[BINARY] [ARGS]...";
static struct argp_option options[] = {
    {0, 0, 0, 0, "Regular"},
    {"json", 'j', 0, 0, "Output as JSON"},
    {0, 0, 0, 0, "Seccomp Strategy"},
    {"c-cpp", 'c', 0},
    {"regular", 'r', 0},
    {0, 0, 0, 0, "Resourse Limit"},
    {"time-limit", 't', "TIME_LIMIT", 0, "TimeLimit, in second"},
    {"memory-limit", 'm', "MEMORY_LIMIT", 0, "MemoryLimit, in MiB"},
    {0},
};

struct arguments {
    int time_limit;
    int memory_limit;
    int json;
    char strategy;
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
        case 'r':
            arguments->strategy = 'r';
            break;
        case 'c':
            arguments->strategy = 'c';
            break;
        case 'j':
            arguments->json = 1;
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
    arguments.memory_limit = 0;
    arguments.time_limit = 0;
    arguments.json = 0;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    pid_t pid;
    if ((pid = fork()) < 0) {
        return SCE_FORK;
    } else if (pid == 0) {

        /* Set Time Limitation */
        if (arguments.time_limit) {
            struct rlimit max_cpu_time;
            max_cpu_time.rlim_cur = max_cpu_time.rlim_max = (rlim_t)(arguments.time_limit + 1);
            if (setrlimit(RLIMIT_CPU, &max_cpu_time) != 0) {
                return SCE_SETRLIMIT;
            }
        }

        /* Set Memory Limitation */
        if (arguments.memory_limit) {
            struct rlimit max_memory;
            max_memory.rlim_cur = max_memory.rlim_max = (rlim_t)(arguments.memory_limit) * 2 * 1024 * 1024;
            if (setrlimit(RLIMIT_AS, &max_memory) != 0) {
                return SCE_SETRLIMIT;
            }
        }

        /* Load Seccomp */
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
        if (arguments.json) {
            printf(R"({"status":%d,"cpuTime":%ld,"memory":%ld})" "\n", status, result.cpu_time, result.memory);
        } else {
            printf("Status: %d, Time: %ldms, Memory: %ldKB\n", status, result.cpu_time, result.memory);
        }
    }

    return 0;
}
