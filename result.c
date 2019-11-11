#include "result.h"
#include <stdio.h>
#include <sys/resource.h>

int ssc_result_parse_rusage(struct ssc_result* result, struct rusage* rusage) {
    result->user_time = (uint64_t)(rusage->ru_utime.tv_sec * 1000 +
                                   rusage->ru_utime.tv_usec / 1000);
    result->sys_time = (uint64_t)(rusage->ru_stime.tv_sec * 1000 +
                                  rusage->ru_stime.tv_usec / 1000);
    result->cpu_time = result->user_time + result->sys_time;
    result->memory = rusage->ru_maxrss;
    return 0;
}

void output_result_to_fd(int fd, struct ssc_result result) {
    dprintf(fd,
            "{\"exitCode\":%d,\"status\":%d,\"signal\":%d,\"cpuTime\":%ld,"
            "\"sysTime\":%ld,\"userTime\":%ld,"
            "\"cgMemory\":%ld,\"cgUserTime\":%ld,"
            "\"cgSysTime\":%ld,\"cgEnabled\":%d,"
            "\"realTime\":%ld,\"memory\":%ld}\n",
            result.exit_code, result.status, result.signal, result.cpu_time,
            result.sys_time, result.user_time, result.cg_mem_maxrss,
            result.cg_cpu_user, result.cg_cpu_sys, result.cg_enabled,
            result.real_time, result.memory);
}