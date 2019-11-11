#include <argp.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <wait.h>

#include "cgroup.h"
#include "result.h"
#include "sandbox.h"
#include "sce.h"
#include "sscts.h"

const char *argp_program_version = "1.0.0";
const char *argp_program_bug_address = "<i@sst.st>";
static char doc[] = "sscts: Sirius Collection - Timer with Seccomp";
static char args_doc[] = "[BINARY] [ARGS]...";
static struct argp_option options[] = {

    {0, 0, 0, 0, "Seccomp Strategy"},
    {"execve-allow", 'x', "SYSTEM_CALL", OPTION_ARG_OPTIONAL,
     "Manually allow execve path (This will ignore all other rules). "
     "If SYSTEM_CALL is not defined, a default rule which can only execve the "
     "first binary will be provided"},

    {0, 0, 0, 0, "Resourse Limit (Hard)"},
    {"time-limit", 't', "SECOND", 0, "TimeLimit, in second"},
    {"memory-limit", 'm', "MiB", 0, "MemoryLimit, in MiB"},
    {"output-limit", 'a', "MiB", 0, "OutputLimit, in MiB"},

    {0, 0, 0, 0, "File Redirect"},
    {"stdout", 'o', "FILE"},
    {"stderr", 'e', "FILE"},
    {"fd", 'f', "fd", 0, "The file descriptor that will output to"},

    {0, 0, 0, 0, "Permission, must call with sudo"},
    {"gid", 'g', "GID"},
    {"uid", 'u', "UID"},

    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 't':
            arguments->time_limit = atoi(arg);
            break;
        case 'm':
            arguments->memory_limit = atoi(arg);
            break;
        case 'a':
            arguments->output_limit = atoi(arg);
            break;
        case 'u':
            arguments->uid = atoi(arg);
            break;
        case 'g':
            arguments->gid = atoi(arg);
            break;
        case 'f':
            arguments->fd = atoi(arg);
            break;
        case 'o':
            arguments->stdout = arg;
            break;
        case 'e':
            arguments->stderr = arg;
            break;
        case 'x':
            arguments->execve_argv[arguments->execve_argc++] = arg;
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

static struct argp argp = {options, parse_opt, args_doc, doc};

pid_t pid;

int is_root;
char cg_cpu[1024], cg_memory[1024];

int main(int argc, char *argv[]) {
    /* Default */
    struct arguments arguments;
    arguments.memory_limit = 0;
    arguments.time_limit = 0;
    arguments.stdout = 0;
    arguments.fd = 1;
    arguments.stderr = 0;
    arguments.gid = -1;
    arguments.uid = -1;
    arguments.output_limit = 0;
    arguments.execve_argc = 0;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    is_root = geteuid() == 0;

    /* Calculate real time consume */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    /* cgroup preparation */
    if (is_root && (access(CGFS_BASE "/cpu/" CGFS_NAME, F_OK) != 0 ||
                    access(CGFS_BASE "/memory/" CGFS_NAME, F_OK) != 0)) {
        if (init_cgroup("cpu")) {
            return SCE_CG;
        }
        if (init_cgroup("memory")) {
            return SCE_CG;
        }
    }
    if (is_root) {
        if (setup_cgroup("cpu", cg_cpu)) {
            return SCE_CG;
        }
        if (setup_cgroup("memory", cg_memory)) {
            return SCE_CG;
        }
    }

    if ((pid = fork()) < 0) {
        return SCE_FORK;
    } else if (pid == 0) {
        if (is_root) {
            int p = getpid();
            if (add_pid_to_cg(p, cg_cpu)) {
                return SCE_CG;
            }
            if (add_pid_to_cg(p, cg_memory)) {
                return SCE_CG;
            }
        }

        /* Redirection */
        FILE *output_file = NULL, *error_file = NULL;

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
            if (output_file &&
                strcmp(arguments.stdout, arguments.stderr) == 0) {
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

        /* Set gid. Root required.*/
        gid_t group_list[] = {arguments.gid};
        if (arguments.gid != -1) {
            if (!is_root) {
                return SCE_RQROOT;
            }
            if (setgid(arguments.gid) == -1 ||
                setgroups(sizeof(group_list) / sizeof(gid_t), group_list) ==
                    -1) {
                return SCE_SGID;
            }
        }

        /* Set uid. Root required. */
        if (arguments.uid != -1) {
            if (!is_root) {
                return SCE_RQROOT;
            }
            if (setuid(arguments.uid) == -1) {
                return SCE_SUID;
            }
        }

        /* Load Seccomp */
        if (arguments.execve_argc) {
            if (ssc_seccomp_load_manually(arguments.bin, arguments.execve_argc,
                                          arguments.execve_argv)) {
                return SCE_LDSCMP;
            }
        }

        if (execvp(arguments.bin, arguments.args)) {
            return SCE_EXEC;
        };
    } else {  // parent
        if (arguments.time_limit) {
            signal(SIGALRM, kill_childprocess);
            alarm(arguments.time_limit + 1);
        }

        int status;
        struct rusage rusage;
        /* wait4 is outdated */
        if (wait4(pid, &status, 2, &rusage) == -1) {
            kill(pid, SIGKILL);
            return SCE_WAIT;
        }

        struct ssc_result result;

        gettimeofday(&end, NULL);
        result.real_time =
            (uint64_t)(end.tv_sec * 1000 + end.tv_usec / 1000 -
                       start.tv_sec * 1000 - start.tv_usec / 1000);
        result.exit_code = WEXITSTATUS(status);
        result.signal = WTERMSIG(status);
        result.status = status;
        ssc_result_parse_rusage(&result, &rusage);

        int fd = arguments.fd;

        if (is_root) {
            result.cg_enabled = 1;
            if (get_cg_result("cpuacct.usage_sys", cg_cpu,
                              &result.cg_cpu_sys)) {
                return SCE_CGRST;
            }
            if (get_cg_result("cpuacct.usage_user", cg_cpu,
                              &result.cg_cpu_user)) {
                return SCE_CGRST;
            }
            if (get_cg_result("memory.max_usage_in_bytes", cg_memory,
                              &result.cg_mem_maxrss)) {
                return SCE_CGRST;
            }
        } else {
            result.cg_cpu_sys = result.cg_cpu_user = result.cg_mem_maxrss =
                result.cg_enabled = 0;
        }

        output_result_to_fd(fd, result);
    }

    return 0;
}
