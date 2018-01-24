/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <assert.h>

#include <nexus_encode.h>

#include <sgx_trts.h>


static inline int
__raw_key_bits(struct nexus_key * key)
{
    switch (key->type) {
	case NEXUS_RAW_256_KEY:    return 256;
	case NEXUS_RAW_128_KEY:    return 128;
	default:                   return -1;
    }

    return -1;
}

static inline int
__raw_key_bytes(struct nexus_key * key)
{
    switch (key->type) {
	case NEXUS_RAW_256_KEY:    return (256 / 8);
	case NEXUS_RAW_128_KEY:    return (128 / 8);
	default:                   return -1;
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


    key->key = nexus_malloc(key_len);


    sgx_read_rand((uint8_t *) key->key, key_len);

    return 0;
}


static int
__raw_copy_key(struct nexus_key * src_key, struct nexus_key * dst_key)
{
    uint32_t key_len = __raw_key_bytes(src_key);

    assert(key_len > 0);

    dst_key->key = nexus_malloc(key_len);

    memcpy(dst_key->key, src_key->key, key_len);

    return 0;
}

static uint8_t *
__raw_key_to_buf(struct nexus_key * key, uint8_t * dst_buf, size_t dst_size)
{
    size_t    key_len = __raw_key_bytes(key);
    uint8_t * tgt_buf = NULL;

    if (dst_buf == NULL) {
	tgt_buf = nexus_malloc(key_len);
    } else {
	if (key_len > dst_size) {
            log_error("destination buffer too small (key_size = %lu) (dst_size = %lu)\n",
                      key_len,
                      dst_size);
            return NULL;
	}

	tgt_buf = dst_buf;
    }

    memcpy(tgt_buf, &key->key, key_len);

    return tgt_buf;
}

static int
__raw_key_from_buf(struct nexus_key * key, uint8_t * src_buf, size_t src_size)
{
    size_t key_len = __raw_key_bytes(key);

    // in case the key exists
    if (key->key) {
	nexus_free(key->key);
    }

    key->key = nexus_malloc(src_size);

    memcpy(&key->key, src_buf, src_size);

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
__raw_key_from_str(struct nexus_key * key, char * key_str)
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
        log_error("Invalid Key length\n");
        return -1;
    }

    return 0;
}
