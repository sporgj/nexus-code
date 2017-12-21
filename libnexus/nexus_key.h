/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>
#include <stdio.h>

typedef enum {
    NEXUS_INVALID_KEY      = 0,
    NEXUS_MBEDTLS_PUB_KEY  = 1,
    NEXUS_MBEDTLS_PRV_KEY  = 2,
    NEXUS_RAW_KEY          = 3
} nexus_key_type_t;

struct nexus_raw_key {
    uint8_t   * key_data;
    uint32_t    key_size;
};


struct nexus_key {
    nexus_key_type_t type;
    
    void * key_state;
};
    


struct nexus_key *
nexus_create_key(nexus_key_type_t key_type);

/* Use this to generate a public key from a private key */
struct nexus_key *
nexus_derive_key(nexus_key_type_t   key_type,
		 struct nexus_key * src_key);


int
nexus_copy_key(struct nexus_key * src_key,
	       struct nexus_key * dst_key);

void
nexus_free_key(struct nexus_key * key);




struct nexus_key *
nexus_key_from_file(nexus_key_type_t   key_type,
		    char             * key_path);

int
nexus_key_to_file(struct nexus_key * key,
		  char             * file_path);

struct nexus_key *
nexus_key_from_str(nexus_key_type_t   key_type,
		   char             * key_str);

char *
nexus_key_to_str(struct nexus_key * key);


char *
nexus_key_type_to_str(nexus_key_type_t type);

nexus_key_type_t
nexus_key_type_from_str(char * type_str);
