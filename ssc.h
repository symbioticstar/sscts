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
};

#endif // SSC_H

