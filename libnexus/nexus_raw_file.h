/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>

int
nexus_read_raw_file(char     * path,
		    uint8_t ** buf,
		    size_t   * size);


int
nexus_write_raw_file(char   * path,
		     void   * buf,
		     size_t   len);


int
nexus_delete_raw_file(char * path);
