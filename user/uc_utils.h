#pragma once
#include <stdlib.h>

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(a,b) a>b?a:b
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include "third/sds.h"

sds do_get_fname(const char * fpath);

sds do_get_dir(const char * fpath);

sds
do_make_path(const char * dirpath, const char * fname);

sds
string_and_number(const char * str, int number);

static inline void do_free(void ** p_ptr) {
    free(*p_ptr);
    *p_ptr = NULL;
}

void hexdump(uint8_t *, uint32_t);

char *
do_absolute_path(const char * path);

int
hash_string(const char * keystring);

uint32_t
murmurhash(const char * key, uint32_t len, uint32_t seed);

#define uerror(...)                   \
    {                                 \
        fprintf(stderr, " ! ");       \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
    }
#define ufatal(...)                                       \
    {                                                     \
        fprintf(stderr, " ! %s:%d ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                     \
        fprintf(stderr, "\n");                            \
    }
#define udebug(...)                                       \
    {                                                     \
        fprintf(stderr, " ! %s %s:%d ", __FUNCTION__,  __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__);                     \
        fprintf(stderr, "\n");                            \
    }
#define uinfo(...)                    \
    {                                 \
        fprintf(stdout, " . ");       \
        fprintf(stdout, __VA_ARGS__); \
        fprintf(stdout, "\n");        \
    }

#ifdef __cplusplus
}
#endif
