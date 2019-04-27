#ifndef SSCTS_H
#define SSCTS_H

struct arguments {
    int time_limit;
    int memory_limit;
    int output_limit;
    int json;
    int uid;
    int gid;
    char strategy;
    int ncts;
    char *bin;
    char *stdin;
    char *stdout;
    char *stderr;
    char *stdans;
    char **args;
};

#endif //SSCTS_H
