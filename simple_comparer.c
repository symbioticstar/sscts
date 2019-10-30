#include <ctype.h>
#include <stdio.h>

#define fgetc fgetc_unlocked
#define BUFF_SIZE (512 * 1024)

FILE *std, *ans;
int s, a;
char b1[BUFF_SIZE];

/**
 * return positive if Accepted
 * return negative if Wrong
 * return zero if not finished
 */
int next() {
    while (s == a) {
        if (!~s) return 1;
        s = fgetc(std);
        a = fgetc(ans);
    }
    if (!~s)
        while (isspace(a)) a = fgetc(ans);
    if (!~a)
        while (isspace(s)) s = fgetc(std);
    if (s == a && !~s) return 2;
    if (isspace(s) && isspace(a)) {
        while (s != '\n' && isspace(s)) s = fgetc(std);
        while (a != '\n' && isspace(a)) a = fgetc(std);
        if (isspace(s)) s = fgetc(std);
        if (isspace(a)) a = fgetc(ans);
        return 0;
    } else {
        return -1;
    }
}

int main(int args, char **argv) {
    if (args != 3) {
        puts("0");
        return 1;
    }
    std = fopen(argv[1], "r"), ans = fopen(argv[2], "r");
    if (!std || !ans) {
        puts("0");
        return 2;
    }
    setvbuf(std, b1, _IOFBF, BUFF_SIZE);
    s = fgetc(std), a = fgetc(ans);
    int result = 0;
    while (!result) {
        result = next();
    }
    printf("%d\n", result);
    return 0;
}