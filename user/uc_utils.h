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

#include "third/sds.h"

sds do_get_fname(const char * fpath);

sds do_get_dir(const char * fpath);

sds
do_make_path(const char * dirpath, const char * fname);

static inline void do_free(void ** p_ptr) {
    free(*p_ptr);
    *p_ptr = NULL;
}

void hexdump(uint8_t *, uint32_t);

char *
do_absolute_path(const char * path);

int
hash_string(const char * keystring);

#ifdef __cplusplus
}
#endif
