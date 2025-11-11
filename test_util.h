#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#ifndef _POSIX_SOURCE
#define _POSIX_SOURCE
#endif //_POSIX_SOURCE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif //_GNU_SOURCE

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KCYN "\x1B[36m"

#define PRINT_TEST_START(name) printf(KCYN "%s:%d --- Starting Test: %s %s ---" KNRM "\n", __FILE__, __LINE__, __func__, name)

#define PRINT_TEST_PASSED() printf(KGRN "--- Test Passed ---" KNRM "\n\n")
#define PRINT_TEST_INFO_GREEN(str) printf(KGRN "%s" KNRM "\n", str)

#define PRINT_TEST_INFO(fmt, ...) printf(KYEL "%s:%d [INFO] " KNRM fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define TEST_ASSERT(cond)                                                                 \
    do {                                                                                  \
        if (!(cond)) {                                                                    \
            fprintf(stderr, KRED "[ASSERT FAIL] %s:%d: %s" KNRM "\n", __FILE__, __LINE__, \
                    #cond);                                                               \
            exit(EXIT_FAILURE);                                                           \
        }                                                                                 \
    } while (0)

#define TEST_ASSERT_EQ(a, b)                                                                                                            \
    do {                                                                                                                                \
        long long __ta = (long long)(a);                                                                                                \
        long long __tb = (long long)(b);                                                                                                \
        if (__ta != __tb) {                                                                                                             \
            fprintf(stderr, KRED "[ASSERT FAIL] %s:%d: %s == %s (got %lld vs %lld)" KNRM "\n", __FILE__, __LINE__, #a, #b, __ta, __tb); \
            exit(EXIT_FAILURE);                                                                                                         \
        } else {                                                                                                                        \
            fprintf(stderr, KGRN "[ASSERT OK] %s:%d: %s == %s (%lld == %lld)" KNRM "\n", __FILE__, __LINE__, #a, #b, __ta, __tb);       \
        }                                                                                                                               \
    } while (0)

#define TEST_ASSERT_MEMEQ(a, b, len)                                                  \
    do {                                                                              \
        if (memcmp((a), (b), (len)) != 0) {                                           \
            fprintf(stderr, KRED "[ASSERT FAIL] %s:%d: memcmp(%s, %s, %s)" KNRM "\n", \
                    __FILE__, __LINE__, #a, #b, #len);                                \
            exit(EXIT_FAILURE);                                                       \
        }                                                                             \
    } while (0)

#define TEST_ASSERT_MEMNEQ(a, b, len)                                                                                                  \
    do {                                                                                                                               \
        if (memcmp((a), (b), (len)) == 0) {                                                                                            \
            fprintf(stderr, KRED "[ASSERT FAIL] %s:%d: memcmp(%s, %s, %s) expected != 0" KNRM "\n", __FILE__, __LINE__, #a, #b, #len); \
            exit(EXIT_FAILURE);                                                                                                        \
        }                                                                                                                              \
    } while (0)

struct test_entry {
    const char *name;
    void (*fn)(void);
};

static inline int run_named_test(const char *name, const struct test_entry *tests, size_t count) {
    if (name) {
        for (size_t i = 0; i < count; i++) {
            if (strcmp(name, tests[i].name) == 0) {
                tests[i].fn();
                return 0;
            }
        }
        fprintf(stderr, "Unknown test: %s\n", name);
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        tests[i].fn();
    }
    return 0;
}

// --- malloc/calloc/realloc/free wrappers for test OOM simulation ---

static size_t malloc_call_count = 0;
static size_t calloc_call_count = 0;
static size_t realloc_call_count = 0;
static size_t free_call_count = 0;

static ssize_t fail_malloc_at = -1;
static ssize_t fail_calloc_at = -1;
static ssize_t fail_realloc_at = -1;

// алиасы дефолтных функций
void *malloc(size_t size) __attribute__((alias("test_malloc")));
void *calloc(size_t nmemb, size_t size) __attribute__((alias("test_calloc")));
void *realloc(void *ptr, size_t size) __attribute__((alias("test_realloc")));
void free(void *ptr) __attribute__((alias("test_free")));

void *test_malloc(size_t size) {
    malloc_call_count++;
    if (fail_malloc_at > 0 && malloc_call_count == (size_t)fail_malloc_at) {
        return NULL;
    }
    void *(*real_malloc)(size_t) = dlsym(RTLD_NEXT, "malloc");
    return real_malloc(size);
}

void *test_calloc(size_t nmemb, size_t size) {
    calloc_call_count++;
    if (fail_calloc_at > 0 && calloc_call_count == (size_t)fail_calloc_at) {
        return NULL;
    }
    void *(*real_calloc)(size_t, size_t) = dlsym(RTLD_NEXT, "calloc");
    return real_calloc(nmemb, size);
}

void *test_realloc(void *ptr, size_t size) {
    realloc_call_count++;
    if (fail_realloc_at > 0 && realloc_call_count == (size_t)fail_realloc_at) {
        return NULL;
    }
    void *(*real_realloc)(void *, size_t) = dlsym(RTLD_NEXT, "realloc");
    return real_realloc(ptr, size);
}

void test_free(void *ptr) {
    free_call_count++;
    void (*real_free)(void *) = dlsym(RTLD_NEXT, "free");
    real_free(ptr);
}

// helper to reset counters and failure points
static inline void reset_alloc_counters(void) {
    malloc_call_count = calloc_call_count = realloc_call_count = free_call_count = 0;
    fail_malloc_at = fail_calloc_at = fail_realloc_at = -1;
}

#endif /* TEST_UTIL_H */
