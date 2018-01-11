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
#include "nexus_log.h"

#include "nexus_key_mbedtls.c"
#include "nexus_key_raw.c"
#include "nexus_key_sealed.c"


void
nexus_free_key(struct nexus_key * key)
{
    switch (key->type) {

	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	case NEXUS_SEALED_128_KEY:
	case NEXUS_SEALED_256_KEY:
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
nexus_init_key(struct nexus_key * key, nexus_key_type_t key_type)
{
    memset(key, 0, sizeof(struct nexus_key));

    key->type = key_type;

    return 0;
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
	    log_error("Invalid key type");
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
	log_error("Could not create key");
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

    int ret   = 0;

    key       = nexus_malloc(sizeof(struct nexus_key));
    
    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_MBEDTLS_PRV_KEY:
	    log_error("Private keys cannot be derived, they must be created\n");
	    goto err;
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_derive_pub_key(key, src_key);
	    break;
	case NEXUS_SEALED_128_KEY:
	    if (src_key->type != NEXUS_RAW_128_KEY) {
		log_error("Error: Can only seal 128 bit RAW key as 128 bit SEALED key\n");
		goto err;
	    }

	    ret = __seal_key(key, src_key);
	    break;
	    
	case NEXUS_SEALED_256_KEY:
	    if (src_key->type != NEXUS_RAW_256_KEY) {
		log_error("Error: Can only seal 256 bit RAW key as 256 SEALED key\n");
		goto err;
	    }

	    ret = __seal_key(key, src_key);
	    break;
	case NEXUS_RAW_128_KEY:
	    if (src_key->type != NEXUS_SEALED_128_KEY) {
		log_error("Error: Can only unseal 128 bit SEALED key in to 128 RAW key\n");
		goto err;
	    }

	    ret = __unseal_key(key, src_key);
	    break;
	case NEXUS_RAW_256_KEY:
	    if (src_key->type != NEXUS_SEALED_256_KEY) {
		log_error("Error: Can only unseal 256 bit SEALED key in to 256 RAW key\n");
		goto err;
	    }

	    ret = __unseal_key(key, src_key);
	    break;
	    

	default:
	    log_error("Invalid key type");
	    goto err;
    }

    if (ret == -1) {
	log_error("Could not create key");
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
	log_error("Could not clone key\n");
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
	case NEXUS_SEALED_128_KEY:
	case NEXUS_SEALED_256_KEY:
	    ret = __sealed_copy_key(src_key, dst_key);
	    break;


	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	default:
	    log_error("Could not copy key for invalid key type");
	    return -1;	
    }
    
    return ret;
}

/* Return Value: 
 *    NULL on error, otherwise a pointer to the buffer serialized into
 *    If dst_buf is NULL, then a new buffer is allocated
 */
uint8_t *
nexus_key_to_buf(struct nexus_key * key,
		 uint8_t          * dst_buf,
		 size_t             dst_size)
{
    uint8_t * buf = NULL;
    
    switch (key->type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    buf = __raw_key_to_buf(key, dst_buf, dst_size);
	    break;
	case NEXUS_SEALED_128_KEY:
	case NEXUS_SEALED_256_KEY:
	    buf = __sealed_key_to_buffer(key, dst_buf, dst_size);
	    break;
	default:
	    log_error("Cannot serialize this key type (%s) to a buffer\n",
		      nexus_key_type_to_str(key->type));
	    return NULL;
    }

    return buf;
}




int
__nexus_key_from_buf(struct nexus_key * key,
		     nexus_key_type_t   key_type, 
		     uint8_t          * src_buf,
		     size_t             src_buflen)
{
    int ret = 0;

    key->type = key_type;
    
    switch (key->type) {
	case NEXUS_RAW_128_KEY:
	case NEXUS_RAW_256_KEY:
	    ret = __raw_key_from_buffer(key, src_buf, src_buflen);
	    break;
	case NEXUS_SEALED_128_KEY:
	case NEXUS_SEALED_256_KEY:
	    ret = __sealed_key_from_buffer(key, src_buf, src_buflen);
	    break;
	default:
	    log_error("Cannot unserialize this key type (%s) from a buffer\n",
		      nexus_key_type_to_str(key->type));
	    return -1;
    }

    return ret;
}


struct nexus_key *
nexus_key_from_buf(nexus_key_type_t   key_type,
		   uint8_t          * src_buf,
		   size_t             src_size)
{
    struct nexus_key * key = NULL;
	
    int ret = 0;

    key = nexus_malloc(sizeof(struct nexus_key));    
    
    ret = __nexus_key_from_buf(key, key_type, src_buf, src_size);
    
    if (ret == -1) {
        log_error("Could not load key from buf");
        goto err;
    }
    
    
    return key;

 err:
    nexus_free(key);
    return NULL;

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
	    log_error("Invalid key type\n");
	    return NULL;
    }

    if (str == NULL) {
	log_error("Could not convert key to string");
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
	    log_error("Invalid key type");
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

    key = nexus_malloc(sizeof(struct nexus_key));    
    
    ret = __nexus_key_from_str(key, key_type, key_str);
    
    if (ret == -1) {
        log_error("Could not load key from string");
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
    if (strncmp(type_str, "NEXUS_MBEDTLS_PUB_KEY", strlen("NEXUS_MBDTLS_PUB_KEY"))  == 0)  return NEXUS_MBEDTLS_PUB_KEY;
    if (strncmp(type_str, "NEXUS_MBEDTLS_PRV_KEY", strlen("NEXUS_MBDTLS_PRV_KEY"))  == 0)  return NEXUS_MBEDTLS_PRV_KEY;
    if (strncmp(type_str, "NEXUS_RAW_128_KEY",     strlen("NEXUS_RAW_128_KEY"))     == 0)  return NEXUS_RAW_128_KEY;
    if (strncmp(type_str, "NEXUS_RAW_256_KEY",     strlen("NEXUS_RAW_256_KEY"))     == 0)  return NEXUS_RAW_256_KEY;

    return NEXUS_INVALID_KEY;
}
