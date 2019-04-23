#ifndef SSC_RESULT_H
#define SSC_RESULT_H

#include <stdint.h>
#include <sys/resource.h>

struct ssc_result {
    uint64_t cpu_time;
    uint64_t real_time;
    uint64_t memory;
    int exit_code; 
    int status;
};

int ssc_result_parse_rusage(struct ssc_result * result, struct rusage * rusage);

#endif //SSC_RESULT_H
