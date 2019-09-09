#include "result.h"
#include <sys/resource.h>

int ssc_result_parse_rusage(struct ssc_result* result, struct rusage* rusage) {
    result->user_time =
        (uint64_t)(rusage->ru_utime.tv_sec * 1000 + rusage->ru_utime.tv_usec / 1000);
    result->sys_time =
        (uint64_t)(rusage->ru_stime.tv_sec * 1000 + rusage->ru_stime.tv_usec / 1000);
    result->cpu_time = result->user_time + result->sys_time;
    result->memory = rusage->ru_maxrss;
    return 0;
}
