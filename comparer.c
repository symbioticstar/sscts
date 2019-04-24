#include <stdio.h>
#include <ctype.h>
// #include "judger.h"
#include "comparer.h"
#include "ssc.h"

/* Judge function of ACM */

void check_space(int *c1, int *c2, FILE *f1, FILE *f2, int *result) {
    while ((isspace(*c1)) || (isspace(*c2))) {
        if (*c1 != *c2) {
            if (*c2 == EOF) {
                for (; isspace(*c1 = fgetc(f1)););
                continue;
            } else if (*c1 == EOF) {
                for (; isspace(*c2 = fgetc(f2)););
                continue;
            } else if ((*c1 == '\r' && *c2 == '\n')) {
                *c1 = fgetc(f1);
            } else if ((*c2 == '\r' && *c1 == '\n')) {
                *c2 = fgetc(f2);
            } else {
                if (result) *result = SCR_PE;
            }
        }
        if (isspace(*c1)) *c1 = fgetc(f1);
        if (isspace(*c2)) *c2 = fgetc(f2);
    }
}

int result_cmp(FILE *f1, FILE *f2, int ncts) {
    int result = SCR_AC;
    int c1,  c2;
    /* No check tailling space (no SCR_PE) */
    int *r = ncts ? 0 : &result;

    if (!f1 || !f2) {
        result =  SCR_SE;
    } else {
        while (1) {
            // Find the first non-space character at the beginning of line.
            // Blank lines are skipped.
            c1 = fgetc(f1);
            c2 = fgetc(f2);
            check_space(&c1, &c2, f1, f2, r);
            // Compare the current line.
            // Read until 2 files return a space or 0 together.
            while ((!isspace(c1) && c1) || (!isspace(c2) && c2)) {
                if (c1 == EOF && c2 == EOF) {
                    return result;
                }
                if (c1 == EOF || c2 == EOF) {
                    break;
                }
                if (c1 != c2) {
                    // Consecutive non-space characters should be all exactly the same
                    result = SCR_WA;
                    return result;
                }
                c1 = fgetc(f1);
                c2 = fgetc(f2);
            }
            check_space(&c1, &c2, f1, f2, r);
            if (c1 == EOF && c2 == EOF) {
                return result;
            }
            if (c1 == EOF || c2 == EOF) {
                result = SCR_WA;
                return result;
            }
            if ((c1 == '\n' || !c1) && (c2 == '\n' || !c2)) {
                break;
            }
        }
    }

    /* Will Not Close File*/
    return result;
}