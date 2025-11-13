#ifndef CLI_HELPER_H
#define CLI_HELPER_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* cli arguments parse macro and functions */
#define NEXT_ARG()                             \
    do {                                       \
        argv++;                                \
        if (--argc <= 0) incomplete_command(); \
    } while (0)

#define NEXT_ARG_OK() (argc - 1 > 0)

#define PREV_ARG() \
    do {           \
        argv--;    \
        argc++;    \
    } while (0)

static inline void incomplete_command(void) {
    fprintf(stdout, "Command line is not complete. Try -h or --help\n");
    exit(-1);
}

static inline bool matches(const char *prefix, const char *string) {
    if (!prefix || !string || !*prefix) return false;
    while (*string && *prefix == *string) {
        prefix++;
        string++;
    }
    return !*prefix;
}

#endif /* CLI_HELPER_H */
