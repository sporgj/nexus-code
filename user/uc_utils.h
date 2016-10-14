#pragma once
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MIN(a,b) (((a)<(b)?(a):(b)))
#define MAX(a,b) (((a)>(b)?(a):(b)))

char * do_get_fname(const char * fpath);

static inline void do_free(void ** p_ptr) {
    free(*p_ptr);
    *p_ptr = NULL;
}

void hexdump(uint8_t *, uint32_t);

#ifdef __cplusplus
}
#endif
