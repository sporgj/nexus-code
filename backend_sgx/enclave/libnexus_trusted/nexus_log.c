/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <stdio.h>


#include "nexus_log.h"
#include "nexus_util.h"

#include "../nexus_enclave_t.h"


void
nexus_printf(char * fmt, ...)
{
    char * log_str = NULL;
    int    size    = 0;
    int    ret     = 0;

    va_list args;
    

    va_start(args, fmt);
    size = vsnprintf(NULL, 0, fmt, args);
    if (size < 0) {
	abort();
    }

    log_str = nexus_malloc(size);

    ret = vsnprintf(log_str, size, fmt, args);
    va_end(args);

    if (ret == -1) {
	abort();
    }
    
    ocall_print(log_str);
    nexus_free(log_str);

    return;
}
    

