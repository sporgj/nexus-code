/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


/* We'll just use mbedtls to generate a random string */

#include <assert.h>

#include <nexus_encode.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>


static inline int
__raw_key_bits(struct nexus_key * key)
{
    switch (key->type) {
	case NEXUS_RAW_256_KEY:        return 256;
	case NEXUS_RAW_128_KEY:        return 128;
	case NEXUS_RAW_GENERIC_KEY:    return (key->raw_bytes << 3);
	default:                       return -1;
    }
    
    return -1;
}

static inline int
__raw_key_bytes(struct nexus_key * key)
{
    switch (key->type) {
	case NEXUS_RAW_256_KEY:        return (256 / 8);
	case NEXUS_RAW_128_KEY:        return (128 / 8);
	case NEXUS_RAW_GENERIC_KEY:    return key->raw_bytes;
	default:                       return -1;
    }
    
    return -1;
}


static int
__raw_create_key(struct nexus_key * key)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context  entropy;
    
    uint32_t key_len = __raw_key_bytes(key);
    int      ret     = 0;
    
    assert(key_len > 0);
    
    key->key = nexus_malloc(key_len);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    if (ret != 0) {
	log_error("Could not seed mbedtls random generator (ret = %d)\n", ret);
	return -1;
    }
    
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, (uint8_t *)(key->key), key_len);

    if (ret != 0) {
	log_error("Could not generate random key (key_len=%u) (ret = %d)\n", key_len, ret);
	return -1;
    }
    
    return 0;
}


static int
__raw_copy_key(struct nexus_key * src_key,
	       struct nexus_key * dst_key)
{
    uint32_t key_len = __raw_key_bytes(src_key);
    
    assert(key_len > 0);

    dst_key->key = nexus_malloc(key_len);
    dst_key->raw_bytes = src_key->raw_bytes;

    memcpy(dst_key->key, src_key->key, key_len);

    return 0;
}


static char *
__raw_key_to_str(struct nexus_key * key)
{
    char   * key_str = NULL;
    uint32_t key_len = __raw_key_bytes(key);

    assert(key_len > 0);

    key_str = nexus_base64_encode(key->key, key_len);

    return key_str;
}


static int
__raw_key_from_str(struct nexus_key * key,
		   char             * key_str)
{
    uint32_t key_len = __raw_key_bytes(key);
    uint32_t dec_len = 0;

    int ret = 0;

    ret = nexus_base64_decode(key_str, (uint8_t **)&(key->key), &dec_len);

    if (ret == -1) {
	log_error("Could not decode raw key from base64\n");
	return -1;
    }
	
    if (dec_len != key_len) {
	log_error("Invalid Key length (length = %u) (expected = %u)\n", dec_len, key_len);
	return -1;
    }

    return 0;
}


static int
__raw_key_to_file(struct nexus_key * key,
		  char             * file_path)
{
    char * key_str = __raw_key_to_str(key);
    int ret = 0;
    
    ret = nexus_write_raw_file(file_path, key_str, strlen(key_str));

    if (ret == -1) {
	log_error("Could not write key file (%s)\n", file_path);
    }
    
    nexus_free(key_str);

    return ret;
}


static int
__raw_key_from_file(struct nexus_key * key,
		    char             * file_path)
{
    char * key_str = NULL;
    size_t key_len = 0;
    int    ret     = 0;

    ret = nexus_read_raw_file(file_path, (uint8_t **)&key_str, &key_len);

    if (ret == -1) {
	log_error("Could not read key file (%s)\n", file_path);
	return -1;
    }

    ret = __raw_key_from_str(key, key_str);

    if (ret == -1) {
	log_error("Could not convert raw key from string (%s)\n", key_str);
    }
    
    nexus_free(key_str);
    
    return ret;
}
