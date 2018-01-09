/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <stdlib.h>
#include <string.h>


#include "nexus_key.h"
#include "nexus_util.h"

#include "nexus_key_mbedtls.c"
#include "nexus_key_raw.c"

#include "../nexus_enclave_t.h"

void
nexus_free_key(struct nexus_key * key)
{
    switch (key->type) {

	case NEXUS_RAW_128_KEY: 
	case NEXUS_RAW_256_KEY: 
	    nexus_free(key->key);
	    break;
	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	    __mbedtls_free_key(key);
	    break;
	default:
	    break;
    }

}




int
nexus_generate_key(struct nexus_key * key,
		   nexus_key_type_t   key_type)
{
    int ret = 0;

    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    ret = __raw_create_key(key);
	    break;
	default:
	    ocall_debug("Invalid key type");
	    return -1;
	    
    }


    return ret;
}

struct nexus_key * 
nexus_create_key(nexus_key_type_t key_type)
{
    struct nexus_key * key = NULL;
    
    int ret = -1;

    key = nexus_malloc(sizeof(struct nexus_key));

    ret = nexus_generate_key(key, key_type);    
    
    if (ret == -1) {
	ocall_debug("Could not create key");
	goto err;
    }

    
    return key;

 err:
    nexus_free(key);
    return NULL;
}


struct nexus_key *
nexus_derive_key(nexus_key_type_t   key_type,
		 struct nexus_key * src_key)
{
    struct nexus_key * key = NULL;

    int ret = 0;

    key       = nexus_malloc(sizeof(struct nexus_key));
    
    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_MBEDTLS_PRV_KEY:
	    ocall_debug("Private keys cannot be derived, they must be created\n");
	    goto err;
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_derive_pub_key(key, src_key);
	    break;

	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	default:
	    ocall_debug("Invalid key type");
	    goto err;
    }

    if (ret == -1) {
	ocall_debug("Could not create key");
	goto err;
    }

    return key;

 err:
    nexus_free(key);
    return NULL;
}


struct nexus_key *
nexus_clone_key(struct nexus_key * src_key)
{
    struct nexus_key * key = NULL;

    int ret = 0;
    
    key = nexus_malloc(sizeof(struct nexus_key));

    key->type = src_key->type;

    ret = nexus_copy_key(key, src_key);

    if (ret == -1) {
	ocall_debug("Could not clone key\n");
	goto err;
    }

    return key;

 err:
    nexus_free(key);
    return NULL;
}

int
nexus_copy_key(struct nexus_key * src_key,
	       struct nexus_key * dst_key)
{   
    int ret = 0;
    
    dst_key->type = src_key->type;

    switch (src_key->type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    ret = __raw_copy_key(src_key, dst_key);
	    break;


	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	default:
	    ocall_debug("Could not copy key for invalid key type");
	    return -1;	
    }
    
    return ret;
}

size_t
nexus_key_buflen(struct nexus_key * key)
{
    switch (key->type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    return __raw_key_bytes(key);

	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	    ocall_debug("Could not copy key for invalid key type");
	    return 0;

	default:
	    return 0;
    }
}

/**
 * Writes the nexus key into the buffer
 * @param key
 * @param buffer is the buffer to write into
 * @param buflen is the size of the buffer
 * @return -1 if the buflen is too small or serialization not supported
 */
int
nexus_key_to_buffer(struct nexus_key * key, uint8_t * buffer, size_t buflen)
{
    switch (key->type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    return __raw_key_to_buffer(key, buffer, buflen);

	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	    ocall_debug("Could not copy key for invalid key type");
	    return -1;

	default:
	    return -1;
    }
}

int
nexus_key_from_buffer(struct nexus_key * key, uint8_t * buffer, size_t buflen)
{
    switch (key->type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    return __raw_key_from_buffer(key, buffer, buflen);

	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	    ocall_debug("Could not copy key for invalid key type");
	    return -1;

	default:
	    return -1;
    }
}

char *
nexus_key_to_str(struct nexus_key * key)
{
    char * str = NULL;


    switch (key->type) {
	
	case NEXUS_MBEDTLS_PRV_KEY:
	    str = __mbedtls_prv_key_to_str(key);
	    break;
	case NEXUS_MBEDTLS_PUB_KEY:
	    str = __mbedtls_pub_key_to_str(key);
	    break;
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    str = __raw_key_to_str(key);
	    break;
	default:
	    ocall_debug("Invalid key type\n");
	    return NULL;
    }

    if (str == NULL) {
	ocall_debug("Could not convert key to string");
    }
    
    return str;
}



int
__nexus_key_from_str(struct nexus_key * key,
		     nexus_key_type_t   key_type,
		     char             * key_str)
{
    int ret = 0;

    key->type = key_type;

    switch (key_type) {
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_pub_key_from_str(key, key_str);
	    break;
	case NEXUS_MBEDTLS_PRV_KEY:
	    ret = __mbedtls_prv_key_from_str(key, key_str);
	    break;
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    ret = __raw_key_from_str(key, key_str);
	    break;
	default:
	    ocall_debug("Invalid key type");
	    return -1;;
    }
    
    return ret;

}


struct nexus_key *
nexus_key_from_str(nexus_key_type_t   key_type,
		   char             * key_str)
{
    struct nexus_key * key = NULL;
	
    int ret = 0;

    key       = nexus_malloc(sizeof(struct nexus_key));    
    
    ret       = __nexus_key_from_str(key, key_type, key_str);
    
    if (ret == -1) {
        ocall_debug("Could not load key from string");
        goto err;
    }
    
    
    return key;

 err:
    nexus_free(key);
    return NULL;
}


char *
nexus_key_type_to_str(nexus_key_type_t type)
{
    switch (type) {
	case NEXUS_MBEDTLS_PUB_KEY: return "NEXUS_MBEDTLS_PUB_KEY";
	case NEXUS_MBEDTLS_PRV_KEY: return "NEXUS_MBEDTLS_PRV_KEY";
	case NEXUS_RAW_128_KEY:     return "NEXUS_RAW_128_KEY";
	case NEXUS_RAW_256_KEY:     return "NEXUS_RAW_256_KEY";
	default:                    return "NEXUS_INVALID_KEY_TYPE";
    }
}


nexus_key_type_t
nexus_key_type_from_str(char * type_str)
{
    if (strncmp(
            type_str, "NEXUS_MBEDTLS_PUB_KEY", strlen("NEXUS_MBDTLS_PUB_KEY"))
        == 0)
        return NEXUS_MBEDTLS_PUB_KEY;
    if (strncmp(
            type_str, "NEXUS_MBEDTLS_PRV_KEY", strlen("NEXUS_MBDTLS_PRV_KEY"))
        == 0)
        return NEXUS_MBEDTLS_PRV_KEY;
    if (strncmp(type_str, "NEXUS_RAW_128_KEY", strlen("NEXUS_RAW_128_KEY"))
        == 0)
        return NEXUS_RAW_128_KEY;
    if (strncmp(type_str, "NEXUS_RAW_256_KEY", strlen("NEXUS_RAW_256_KEY"))
        == 0)
        return NEXUS_RAW_256_KEY;

    return NEXUS_INVALID_KEY;
}
