/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "nexus_uuid.h"

#include <stdlib.h>

#define nexus_free(ptr)                                                        \
    do {                                                                       \
        free(ptr);                                                             \
        ptr = NULL;                                                            \
    } while (0)


static inline int min(int a, int b) {
    if (a > b)
        return b;
    return a;
}

static inline int max(int a, int b) {
    if (a > b)
        return a;
    return b;
}

void * nexus_malloc(size_t size);


#ifdef __cplusplus
}
#endif
