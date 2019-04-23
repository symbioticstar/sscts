#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <unistd.h>
#include <grp.h>
#include <string.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sandbox.h"
#include "result.h"
#include "ssc.h"

const char *argp_program_version = "0.3.0";
const char *argp_program_bug_address = "<i@sst.st>";
static char doc[] = "SSX Online Judge Core - C version";
static char args_doc[] = "[BINARY] [ARGS]...";
static struct argp_option options[] = {
    {0, 0, 0, 0, "Regular"},
    {"json", 'j', 0, 0, "Output as JSON"},
    {0, 0, 0, 0, "Seccomp Strategy"},
    {"c-cpp", 'c', 0},
    {"regular", 'r', 0},
    {"no-seccomp", 'n', 0, 0, "Execute without seccomp"},
    {0, 0, 0, 0, "Resourse Limit"},
    {"time-limit", 't', "SECOND", 0, "TimeLimit, in second"},
    {"memory-limit", 'm', "MiB", 0, "MemoryLimit, in MiB"},
    {"output-limit", 'a', "MiB", 0, "OutputLimit, in MiB"},
    {0, 0, 0, 0, "File Redirect"},
    {"stdin", 'i', "FILE" },
    {"stdout", 'o', "FILE" },
    {"stderr", 'e', "FILE" },
    {0, 0, 0, 0, "Permission, must call with sudo"},
    {"gid", 'g', "GID"},
    {"uid", 'u', "UID"},
    {0},
};

struct arguments {
    int time_limit;
    int memory_limit;
    int output_limit;
    int json;
    int uid;
    int gid;
    char strategy;
    char *bin;
    char *stdin;
    char *stdout;
    char *stderr;
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
        case 'u':
            arguments->uid = atoi(arg);
            break;
        case 'g':
            arguments->gid = atoi(arg);
            break;
        case 'r':
            arguments->strategy = 'r';
            break;
        case 'c':
            arguments->strategy = 'c';
            break;
        case 'n':
            arguments->strategy = 0;
            break;
        case 'j':
            arguments->json = 1;
            break;
        case 'i':
            arguments->stdin = arg;
            break;
        case 'o':
            arguments->stdout = arg;
            break;
        case 'e':
            arguments->stderr = arg;
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
    /* Default */
    struct arguments arguments;
    arguments.strategy = 'c';
    arguments.memory_limit = 0;
    arguments.time_limit = 0;
    arguments.json = 0;
    arguments.stdin = 0;
    arguments.stdout = 0;
    arguments.stderr = 0;
    arguments.gid = -1;
    arguments.uid = -1;
    arguments.output_limit = 0;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    /* Calculate real time consume */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    pid_t pid;
    if ((pid = fork()) < 0) {
        return SCE_FORK;
    } else if (pid == 0) {
        /* Redirection */
        FILE *input_file = NULL, *output_file = NULL, *error_file = NULL;
        if (arguments.stdin) {
            input_file = fopen(arguments.stdin, "r");
            if (input_file == NULL) {
                return SCE_NOENT;
            }
            if (dup2(fileno(input_file), fileno(stdin)) == -1) {
                return SCE_DUP2;
            }
        }
        if (arguments.stdout) {
            output_file = fopen(arguments.stdout, "w");
            if (output_file == NULL) {
                return SCE_PERM;
            }
            if (dup2(fileno(output_file), fileno(stdout)) == -1) {
                return SCE_DUP2;
            }
        }
        if (arguments.stderr) {
            if (output_file && strcmp(arguments.stdout, arguments.stderr) == 0) {
                error_file = output_file;
            } else {
                error_file = fopen(arguments.stderr, "w");
                if (error_file == NULL) {
                    return SCE_PERM;
                }
            }
            if (dup2(fileno(error_file), fileno(stderr)) == -1) {
                return SCE_DUP2;
            }
        }

        /* Set Output Limitation */
        if (arguments.output_limit) {
            struct rlimit output_limit;
            output_limit.rlim_cur = output_limit.rlim_max = (rlim_t)arguments.output_limit * 1024 * 1024;
            if (setrlimit(RLIMIT_FSIZE, &output_limit) != 0) {
                return SCE_SETRLIMIT;
            }
        }

        /* Set Time Limitation */
        if (arguments.time_limit) {
            struct rlimit max_time;
            max_time.rlim_cur = max_time.rlim_max = (rlim_t)arguments.time_limit + 1;
            if (setrlimit(RLIMIT_CPU, &max_time) != 0) {
                return SCE_SETRLIMIT;
            }
            if (setrlimit(RLIMIT_RTTIME, &max_time) != 0) {
                return SCE_SETRLIMIT;
            }
        }

        /* Set Memory Limitation */
        if (arguments.memory_limit) {
            struct rlimit max_memory;
            max_memory.rlim_cur = max_memory.rlim_max = (rlim_t)arguments.memory_limit * 2 * 1024 * 1024;
            if (setrlimit(RLIMIT_AS, &max_memory) != 0) {
                return SCE_SETRLIMIT;
            }
        }

        /* Set gid. Root required.*/
        gid_t group_list[] = {arguments.gid };
        if (arguments.gid  != -1) {
            if (geteuid() != 0) {
                return SCE_RQROOT;
            }
            if (setgid(arguments.gid) == -1 || setgroups(sizeof(group_list) / sizeof(gid_t), group_list) == -1) {
                return SCE_SGID;
            }
        }

        /* Set uid. Root required. */
        if (arguments.uid  != -1) {
            if (geteuid() != 0) {
                return SCE_RQROOT;
            }
            if (setuid(arguments.uid) == -1) {
                return SCE_SUID;
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

        char* envp[] = { "PATH=/home/sirius/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:.", 0 };

        execve(arguments.bin, arguments.args, envp);
    } else {
        int status;
        struct rusage rusage;
        if (wait4(pid, &status, WSTOPPED, &rusage) == -1) {
            kill(pid, SIGKILL);
            return SCE_WAIT;
        }

        struct ssc_result result;

        gettimeofday(&end, NULL);
        result.real_time = (uint64_t)(end.tv_sec * 1000 + end.tv_usec / 1000 - start.tv_sec * 1000 - start.tv_usec / 1000);


        result.exit_code = WEXITSTATUS(status);
        result.status = status;
        ssc_result_parse_rusage(&result, &rusage);
        if (arguments.json) {
            printf("{\"exitCode\":%d,status\":%d,\"cpuTime\":%ld,"
                   "\"realTime\":%ld,\"memory\":%ld}\n", result.exit_code, result.status, result.cpu_time,
                   result.real_time, result.memory);
        } else {
            printf(
                "----------------"
                "\nExitCode: %d\n"
                "Status:   %d\n"
                "CPUTime:  %ldms\n"
                "RealTime: %ldms\n"
                "Memory:   %ldKB\n"
                ANSI_COLOR_RED
                "\nCopyright SS, 2019\n"
                ANSI_COLOR_RESET,
                result.exit_code, result.status,
                result.cpu_time, result.real_time, result.memory);
        }
    }

    return 0;
}