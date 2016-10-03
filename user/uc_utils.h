#pragma once
#include <stdlib.h>

char * do_get_fname(const char * fpath);

static inline void do_free(void ** p_ptr) {
    free(*p_ptr);
    *p_ptr = NULL;
}
