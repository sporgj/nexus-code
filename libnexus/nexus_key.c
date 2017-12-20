/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <stdlib.h>



#include <nexus_key.h>
#include <nexus_util.h>
#include <nexus_log.h>
#include <nexus_raw_file.h>

#include "nexus_key_mbedtls.c"


void
nexus_free_key(struct nexus_key * key)
{
    switch (key->type) {

	case NEXUS_RAW_KEY: {
	    struct nexus_raw_key * raw_key = key->key_state;

	    nexus_free(raw_key->key_data);
	    break;
	}
	case NEXUS_MBEDTLS_PUB_KEY:
	case NEXUS_MBEDTLS_PRV_KEY:
	    __mbedtls_free_key(key);
	    break;
	default:
	    break;
    }

}




struct nexus_key * 
nexus_create_key(nexus_key_type_t key_type)
{
    struct nexus_key * key = NULL;
    
    int ret = -1;

    key = calloc(sizeof(struct nexus_key), 1);

    if (key == NULL) {
	log_error("Could not allocate nexus_key\n");
	return NULL;
    }

    
    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_MBEDTLS_PRV_KEY:
	    ret = __mbedtls_create_prv_key(key);
	    break;
	case NEXUS_MBEDTLS_PUB_KEY:
	    log_error("Public keys can only be derived from pre-existing private keys <see nexus_derive_key()>\n");
	    goto err;
	case NEXUS_RAW_KEY:
	default:
	    log_error("Invalid key type: %d\n", key_type);
	    goto err;
	    
    }

    if (ret == -1) {
	log_error("Could not create key (type=%s) (ret = %d)\n",
		  nexus_key_type_to_str(key_type),
		  ret);
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

    key = calloc(sizeof(struct nexus_key), 1);

    if (key == NULL) {
	log_error("Could not allocate nexus_key\n");
	return NULL;
    }

    
    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_MBEDTLS_PRV_KEY:
	    log_error("Private keys cannot be derived, they must be created\n");
	    goto err;
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_derive_pub_key(key, src_key);
	    break;
	case NEXUS_RAW_KEY:
	default:
	    log_error("Invalid key type: %d\n", key_type);
	    goto err;
    }

    if (ret == -1) {
	log_error("Could not create key (type=%s) (ret = %d)\n",
		  nexus_key_type_to_str(key_type),
		  ret);
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
	case NEXUS_RAW_KEY:
	default:
	    log_error("Invalid key type (type = %d)\n", key->type);
	    return NULL;
    }

    if (str == NULL) {
	log_error("Could not convert key to string (type = %s)\n",
		  nexus_key_type_to_str(key->type));
    }
    
    return str;
}



struct nexus_key *
nexus_key_from_str(nexus_key_type_t   key_type,
		   char             * key_str)
{
    struct nexus_key * key = NULL;
	
    int ret = 0;

    
    key = calloc(sizeof(struct nexus_key), 1);

    if (key == NULL) {
	log_error("Could not allocate nexus_key\n");
	return NULL;
    }
    
    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_pub_key_from_str(key, key_str);
	    break;
	case NEXUS_MBEDTLS_PRV_KEY:
	    ret = __mbedtls_prv_key_from_str(key, key_str);
	    break;
	case NEXUS_RAW_KEY:
	default:
	    log_error("Invalid key type: %d\n", key_type);
	    goto err;
    }

    if (ret == -1) {
	log_error("Could not load key from string (type=%s) (str=%s) (ret = %d)\n",
		  nexus_key_type_to_str(key_type),
		  key_str,
		  ret);
	return NULL;
    }
    
    
    return key;

 err:
    nexus_free(key);
    return NULL;
}


int
nexus_key_to_file(struct nexus_key * key,
		  char             * file_path)
{

    int ret = 0;
    
    switch (key->type) {
	case NEXUS_MBEDTLS_PRV_KEY:
	    ret = __mbedtls_prv_key_to_file(key, file_path);
	    break;
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_pub_key_to_file(key, file_path);
	    break;
	case NEXUS_RAW_KEY:
	default:
	    log_error("Invalid key type (type = %d)\n", key->type);
	    return -1;
    }

    if (ret == -1) {
	log_error("Could not store key (type = %s) to file (%s)\n",
		  nexus_key_type_to_str(key->type),
		  file_path);
    }
    

    return ret;
}


struct nexus_key * 
nexus_key_from_file(nexus_key_type_t   key_type,
		    char             * key_path)
{
    struct nexus_key * key = NULL;

    int ret = 0;
    
    key = calloc(sizeof(struct nexus_key), 1);

    if (key == NULL) {
	log_error("Could not allocate nexus_key\n");
	return NULL;
    }

    key->type = key_type;
    
    switch (key_type) {
	case NEXUS_MBEDTLS_PUB_KEY:
	    ret = __mbedtls_pub_key_from_file(key, key_path);
	    break;
	case NEXUS_MBEDTLS_PRV_KEY:
	    ret = __mbedtls_prv_key_from_file(key, key_path);
	    break;
	case NEXUS_RAW_KEY:
	default:
	    log_error("Invalid key type: %d\n", key_type);
	    goto err;
    }

    if (ret == -1) {
	log_error("Could not load key from file (type=%s) (file=%s) (ret = %d)\n",
		  nexus_key_type_to_str(key_type),
		  key_path,
		  ret);
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
	case NEXUS_RAW_KEY:         return "NEXUS_RAW_KEY";
	default:                    return "NEXUS_INVALID_KEY_TYPE";
    }
}


nexus_key_type_t
nexus_key_type_from_str(char * type_str)
{
    if (strncmp(type_str, "NEXUS_MBEDTLS_PUB_KEY", strlen("NEXUS_MBDTLS_PUB_KEY")) == 0) return NEXUS_MBEDTLS_PUB_KEY;
    if (strncmp(type_str, "NEXUS_MBEDTLS_PRV_KEY", strlen("NEXUS_MBDTLS_PRV_KEY")) == 0) return NEXUS_MBEDTLS_PRV_KEY;
    if (strncmp(type_str, "NEXUS_RAW_KEY",         strlen("NEXUS_RAW_KEY"))        == 0) return NEXUS_RAW_KEY;

    return NEXUS_INVALID_KEY;
}