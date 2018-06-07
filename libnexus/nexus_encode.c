/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nexus_log.h>
#include <nexus_util.h>

/* Alternate Nexus alphabet for base64 encoding
 * Padding Character is '.' 
 */
static const char alt64_table[] = ("ABCDEFGHIJKLMNOPQRSTU"
				   "VWXYZabcdefghijklmnop"
				   "qrstuvwxyz0123456789-_");

const char * base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char * hex_table    = "0123456789abcdef";




int
nexus_alt64_decode(char      * alt64_str,
		   uint8_t  ** dst,
		   uint32_t  * dst_len)
{
    uint8_t * out_buf = NULL;
    uint32_t  out_len = 0;

    int num_chunks = 0;
    int padding    = 0;
    int i          = 0;
    int len        = 0;

    
    if (alt64_str == 0) {
	log_error("Error: Could not parse empty String\n");
        return -1;
    }

    len = strlen(alt64_str);
    
    if (len % 4) {
        log_error("Invalid Alt64 Length\n");
        return -1;
    }
   
    num_chunks = len / 4;

    if (index(alt64_str, '.')) {
        padding = (alt64_str + len) - index(alt64_str, '.');
    }

    out_len = (num_chunks * 3) - padding;
    out_buf = (uint8_t *)nexus_malloc(out_len);

    for (i = 0; i < num_chunks; i++) {
        char  * chunk   = (char *)alt64_str + (i * 4);
        uint8_t vals[4] = {0, 0, 0, 0};
        
        vals[0] = index(alt64_table, (int)chunk[0]) - alt64_table;
        vals[1] = index(alt64_table, (int)chunk[1]) - alt64_table;

        if (index(alt64_table, (int)chunk[2]) != NULL) {
            vals[2] = index(alt64_table, (int)chunk[2]) - alt64_table;
        }

        if (index(alt64_table, (int)chunk[3]) != NULL) {
            vals[3] = index(alt64_table, (int)chunk[3]) - alt64_table;
        }


        out_buf[(i * 3) + 0] = ((vals[0] & 0x3f) << 2) | ((vals[1] & 0x30) >> 4);


        if ((padding > 0) || (i != num_chunks - 1)){
            out_buf[(i * 3) + 1] = ((vals[1] & 0x0f) << 4) | ((vals[2] & 0x3c) >> 2);
        }

        if ((padding > 1) || (i != num_chunks - 1)) {
            out_buf[(i * 3) + 2] = ((vals[2] & 0x03) << 6) | ((vals[3] & 0x3f));
        }
    }

    *dst     = out_buf;
    *dst_len = out_len;

    return 0;
}


char *
nexus_alt64_encode(uint8_t  * src_buf,
		   uint32_t   src_len)
{
    char    * alt64_str  = NULL;
    uint32_t  num_chunks = (src_len / 3);
    uint32_t  i = 0;


    if (src_len % 3) {
        num_chunks++;
    }


    alt64_str = nexus_malloc((num_chunks * 4) + 1);

    if (alt64_str == NULL) {
	log_error("Could not allocate alt64 string\n");
	return NULL;
    }

    for (i = 0; i < num_chunks; i++) {
        uint8_t chunk[3] = {0, 0, 0};
        int j = 0;

        chunk[0] = src_buf[i * 3];

        if ((i * 3) + 1 < src_len ) {
            chunk[1] = src_buf[(i * 3) + 1];
        }

        if ((i * 3) + 2 < src_len ) {
            chunk[2] = src_buf[(i * 3) + 2];
        }
        

        for (j = 0; j < 4; j++) {
            uint8_t val = 0;
            uint8_t c   = 0;

            if (j == 0) {
                val = (chunk[0] >> 2);
            } else if (j == 1) {
                val = (chunk[1] >> 4) | ((chunk[0] & 0x03) << 4);
            } else if (j == 2) {
                val = (chunk[2] >> 6) | ((chunk[1] & 0x0f) << 2);
            } else {
                val = chunk[2] & 0x3f;
            }
            

            c = alt64_table[val];

            /* Bounds checking */
            if (j >= 2) {
                if (((i * 3) + (j - 1)) >= src_len) {
                    c = '.';
                }
            }

	    alt64_str[(i * 4) + j] = c;
        }
    }

    return alt64_str;

}





int
nexus_base64_decode(char      * base64_str,
		    uint8_t  ** dst,
		    uint32_t  * dst_len)
{
    uint8_t * out_buf = NULL;
    uint32_t  out_len = 0;

    int num_chunks = 0;
    int padding    = 0;
    int i          = 0;
    int len        = 0;

    
    if (base64_str == 0) {
	log_error("Error: Could not parse empty String\n");
        return -1;
    }
    
    len = strlen(base64_str);

    if (len % 4) {
        log_error("Invalid Base64 Length\n");
        return -1;
    }
   
    num_chunks = len / 4;

    if (index(base64_str, '=')) {
        padding = (base64_str + len) - index(base64_str, '=');
    }

    out_len = (num_chunks * 3) - padding;
    out_buf = (uint8_t *)calloc(1, out_len);

    for (i = 0; i < num_chunks; i++) {
        char  * chunk   = (char *)base64_str + (i * 4);
        uint8_t vals[4] = {0, 0, 0, 0};
        
        vals[0] = index(base64_table, (int)chunk[0]) - base64_table;
        vals[1] = index(base64_table, (int)chunk[1]) - base64_table;

        if (index(base64_table, (int)chunk[2]) != NULL) {
            vals[2] = index(base64_table, (int)chunk[2]) - base64_table;
        }

        if (index(base64_table, (int)chunk[3]) != NULL) {
            vals[3] = index(base64_table, (int)chunk[3]) - base64_table;
        }


        out_buf[(i * 3) + 0] = ((vals[0] & 0x3f) << 2) | ((vals[1] & 0x30) >> 4);


        if ((padding > 0) || (i != num_chunks - 1)){
            out_buf[(i * 3) + 1] = ((vals[1] & 0x0f) << 4) | ((vals[2] & 0x3c) >> 2);
        }

        if ((padding > 1) || (i != num_chunks - 1)) {
            out_buf[(i * 3) + 2] = ((vals[2] & 0x03) << 6) | ((vals[3] & 0x3f));
        }
    }

    *dst     = out_buf;
    *dst_len = out_len;

    return 0;
}


char *
nexus_base64_encode(uint8_t  * src_buf,
		    uint32_t   src_len)
{
    char    * base64_str  = NULL;
    uint32_t  num_chunks = (src_len / 3);
    uint32_t  i = 0;


    if (src_len % 3) {
        num_chunks++;
    }


    base64_str = calloc(1, (num_chunks * 4) + 1);

    if (base64_str == NULL) {
	log_error("Could not allocate base64 string\n");
	return NULL;
    }

    for (i = 0; i < num_chunks; i++) {
        uint8_t chunk[3] = {0, 0, 0};
        int j = 0;

        chunk[0] = src_buf[i * 3];

        if ((i * 3) + 1 < src_len ) {
            chunk[1] = src_buf[(i * 3) + 1];
        }

        if ((i * 3) + 2 < src_len ) {
            chunk[2] = src_buf[(i * 3) + 2];
        }
        

        for (j = 0; j < 4; j++) {
            uint8_t val = 0;
            uint8_t c   = 0;

            if (j == 0) {
                val = (chunk[0] >> 2);
            } else if (j == 1) {
                val = (chunk[1] >> 4) | ((chunk[0] & 0x03) << 4);
            } else if (j == 2) {
                val = (chunk[2] >> 6) | ((chunk[1] & 0x0f) << 2);
            } else {
                val = chunk[2] & 0x3f;
            }
            

            c = base64_table[val];

            /* Bounds checking */
            if (j >= 2) {
                if (((i * 3) + (j - 1)) >= src_len) {
                    c = '=';
                }
            }

	    base64_str[(i * 4) + j] = c;
        }
    }

    return base64_str;

}



/* 
 * There doesn't seem to be _any_ base58 implementation out there that isn't 
 * a pile of shit. So I guess we're fucking doing this....
 */


/* What the hell is base58 anyway?
 * Encoding:
 * 1: Convert input buffer to a single number
 * 2: Successively divide number by 58, recording remainder using the alphabet (base58_table)
 *      Results are prepended to the output string
 * 3: Continue until number is zero
 * 4. Leading zeroes are not encoded, but rather replaced with "1"'s at start of output string
 */


// static const char * base58_table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
 


int
nexus_base58_encode(uint8_t  * in_buf,
		    size_t     in_size,
		    uint8_t ** out_buf,
		    size_t   * out_size)
{
    //    uint8_t * enc_buf  = NULL;
    //    size_t    enc_size = 0;

    int num_zeroes = 0;
    size_t offset    = 0;
    
    // Count the number of leading zeroes
    for (offset = 0; offset < in_size; offset++) {

	if (in_buf[offset] != 0) {
	    break;
	}

	num_zeroes++;
    }
    
    // Calculate size needed and allocate it
	
    // start processing

    
    
    return -1;

}
