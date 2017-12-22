/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>


int dispatch_nexus_command(uint8_t   * cmd_buf,
			   uint32_t    cmd_size,
			   uint8_t  ** resp_buf,
			   uint32_t  * resp_size);
