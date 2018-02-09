/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <nexus_util.h>


void *
nexus_malloc(size_t size)
{
    void * ptr = NULL;

    ptr = calloc(size, 1);

    if (ptr == NULL) {
	abort();
    }

    return ptr;
}
