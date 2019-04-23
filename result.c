#include <sys/resource.h>
#include "result.h"

int ssc_result_parse_rusage(struct ssc_result * result, struct rusage * rusage) {
    result->cpu_time = (int)(rusage->ru_utime.tv_sec * 1000 +
                              rusage->ru_utime.tv_usec / 1000) +
                        (int)(rusage->ru_stime.tv_sec * 1000 +
                              rusage->ru_stime.tv_usec / 1000);
    result->memory = rusage->ru_maxrss;
    return 0;
}
