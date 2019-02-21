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

/**
 * Splits path into malloced dirpath and filename components
 */
void
nexus_splitpath(const char * filepath, char ** dirpath, char ** filename);

void nexus_hexdump(void * ptr, size_t size);

int nexus_copy_file(const char * src_filepath, const char * dst_filepath);

int nexus_strtoi8 (char * str, int8_t   * value);
int nexus_strtou8 (char * str, uint8_t  * value);
int nexus_strtoi16(char * str, int16_t  * value);
int nexus_strtou16(char * str, uint16_t * value);
int nexus_strtoi32(char * str, int32_t  * value);
int nexus_strtou32(char * str, uint32_t * value);
int nexus_strtoi64(char * str, int64_t  * value);
int nexus_strtou64(char * str, uint64_t * value);


void nexus_print_backtrace();

#ifdef __cplusplus
}
#endif
