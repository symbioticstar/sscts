#ifndef SSC_H
#define SSC_H

enum ssc_error {
    SUCCESS,
    ERROR,
    SCE_LDSCMP,
    SCE_FORK,
    SCE_SETRLIMIT,
    SCE_NOENT,
    SCE_DUP2,
    SCE_PERM,
    SCE_WAIT,
    SCE_SGID,
    SCE_SUID,
    SCE_RQROOT,
    SCE_RQOF,
    SCE_EXECVE,
};

enum ssc_judge_result {
    SCR_AC,
    SCR_WA,
    SCR_PE,
    SCR_SE,
};

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#endif // SSC_H

