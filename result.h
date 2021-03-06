#ifndef SSC_RESULT_H
#define SSC_RESULT_H

#include <stdint.h>
#include <sys/resource.h>

struct ssc_result {
    uint64_t cpu_time;
    uint64_t user_time;
    uint64_t sys_time;
    uint64_t real_time;
    uint64_t memory;
    int cg_enabled;
    int exit_code;
    int status;
    int signal;
};

void ssc_result_parse_rusage(struct ssc_result* result, struct rusage* rusage);
void output_result_to_fd(int fd, struct ssc_result result);

#endif  // SSC_RESULT_H
