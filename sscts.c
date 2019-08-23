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
#include <signal.h>

#include "result.h"
#include "ssc.h"
#include "sscts.h"

const char *argp_program_version = "1.0.0";
const char *argp_program_bug_address = "<i@sst.st>";
static char doc[] = "SSCTS Miminized";
static char args_doc[] = "[BINARY] [ARGS]...";

static struct argp_option options[] = {
    {"fd", 'f', "fd", 0, "Output to file descriptor"},
    {0}
};


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 'f':
            arguments->fd = atoi(arg);
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

pid_t pid;


int main(int argc, char *argv[]) {
    /* Default */
    struct arguments arguments;
    arguments.fd = 1;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    /* Calculate real time consume */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    if ((pid = fork()) < 0) {
        return SCE_FORK;
    } else if (pid == 0) {
        /* Redirection */
        char path[1000];
        sprintf(path, "PATH=%s", getenv("PATH"));
        char* envp[] = {path, 0 };

        if (execve(arguments.bin, arguments.args, envp)) {
            return SCE_EXECVE;
        };
    } else {

        int status;
        struct rusage rusage;
        /* wait4 is deprecated */
        if (wait4(pid, &status, WSTOPPED, &rusage) == -1) {
            kill(pid, SIGKILL);
            return SCE_WAIT;
        }

        struct ssc_result result;

        gettimeofday(&end, NULL);
        result.real_time = (uint64_t)(end.tv_sec * 1000 + end.tv_usec / 1000 - start.tv_sec * 1000 - start.tv_usec / 1000);


        result.exit_code = WEXITSTATUS(status);
        result.signal = WTERMSIG(status);
        result.status = status;
        ssc_result_parse_rusage(&result, &rusage);

        int fd = arguments.fd;

        dprintf(fd, "{\"exitCode\":%d,\"status\":%d,\"signal\":%d,\"cpuTime\":%ld,"
                "\"realTime\":%ld,\"memory\":%ld}\n",
                result.exit_code, result.status, result.signal, result.cpu_time,
                result.real_time, result.memory);
    }

    return 0;
}
