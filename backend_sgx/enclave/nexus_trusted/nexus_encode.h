/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#pragma once

int
nexus_alt64_decode(char      * alt_str,
		   uint8_t  ** dst,
		   uint32_t  * dst_len);

char *
nexus_alt64_encode(uint8_t   * src_buf,
		   uint32_t    src_len);

int
nexus_base64_decode(char      * alt_str,
		    uint8_t  ** dst,
		    uint32_t  * dst_len);

char *
nexus_base64_encode(uint8_t   * src_buf,
		    uint32_t    src_len);
