#ifndef SSCTS_H
#define SSCTS_H

struct arguments {
    int time_limit;
    int memory_limit;
    int output_limit;
    int uid;
    int gid;
    char strategy;
    int fd;
    int execve_argc;
    char *bin;
    char *stdin;
    char *stdout;
    char *stderr;
    char *stdans;
    char **args;
    char *execve_argv[20];
};

#endif //SSCTS_H
