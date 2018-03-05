/*
 * Copyright (c) 2018, Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <assert.h>

#include <nexus_encode.h>

struct __volkey {
    int len;

    sgx_sealed_data_t * data;
};

int
__vol_key_bytes(struct nexus_key * key)
{
    struct __volkey * vkey = (struct __volkey *)key->key;

    if ((key->type == NEXUS_SEALED_VOLUME_KEY) && (vkey != NULL)) {
	return vkey->len;
    }

    return -1;
}

sgx_sealed_data_t *
__vol_key_data(struct nexus_key * key)
{
    struct __volkey * vkey = (struct __volkey *)key->key;

    if ((key->type == NEXUS_SEALED_VOLUME_KEY) && (vkey != NULL)) {
	return vkey->data;
    }

    return NULL;
}

static struct __volkey *
__alloc_volkey(int len) {
    struct __volkey * vkey = NULL;

    vkey = nexus_malloc(sizeof(struct __volkey));

    vkey->len = len;
    vkey->data = nexus_malloc(len);

    return vkey;
}

int
__vol_key_create_key(struct nexus_key * key, sgx_sealed_data_t * data, int len)
{
    struct __volkey  * vkey = NULL;

    vkey = __alloc_volkey(len);

    memcpy(vkey->data, data, len);

    key->key  = vkey;
    key->type = NEXUS_SEALED_VOLUME_KEY;

    return 0;
}

struct nexus_key *
vol_key_create_key(sgx_sealed_data_t * data, int len)
{
    struct nexus_key * key  = NULL;

    key = nexus_malloc(sizeof(struct nexus_key));

    __vol_key_create_key(key, data, len);

    return key;
}

static int
__vol_key_unseal(struct nexus_key * unsealed_raw_key, struct nexus_key * sealed_volkey)
{
    sgx_sealed_data_t * sealed_data = __vol_key_data(sealed_volkey);

    uint32_t unsealed_len = 0;

    int ret = -1;


    unsealed_len = sgx_get_encrypt_txt_len(sealed_data);

    unsealed_raw_key->key = nexus_malloc(unsealed_len);

    ret = sgx_unseal_data(sealed_data, NULL, 0, unsealed_raw_key->key, &unsealed_len);

    if (ret != 0) {
        log_error("sgx_unseal_data FAILED \n");
        return -1;
    }

    return 0;
}

static int
__vol_key_seal(struct nexus_key * sealed_volkey, struct nexus_key * raw_key)
{
    size_t key_size = __raw_key_bytes(raw_key);

    sgx_sealed_data_t * sealed_data = NULL;

    size_t sealed_len = 0;

    int ret = -1;


    sealed_len  = sgx_calc_sealed_data_size(0, key_size);

    sealed_data = nexus_malloc(sealed_len);

    ret = sgx_seal_data(0, NULL, key_size, raw_key->key, sealed_len, sealed_data);

    if (ret != 0) {
        nexus_free(sealed_data);
        log_error("sgx_seal_data() FAILED\n");
        return -1;
    }

    return __vol_key_create_key(sealed_volkey, sealed_data, sealed_len);
}

void
__vol_key_free(struct nexus_key * key)
{
    struct __volkey * vkey = (struct __volkey *)key->key;

    nexus_free(vkey->data);
    nexus_free(vkey);
}

static int
__vol_key_copy_key(struct nexus_key * src_key, struct nexus_key * dst_key)
{
    struct __volkey * src_volkey  = NULL;
    struct __volkey * dst_volkey  = NULL;

    uint32_t key_len = __vol_key_bytes(src_key);

    assert(key_len > 0);


    src_volkey = (struct __volkey *)(src_key->key);
    dst_volkey = __alloc_volkey(key_len);

    memcpy(dst_volkey->data, src_volkey->data, key_len);

    dst_key->key = dst_volkey;

    return 0;
}

static uint8_t *
__vol_key_to_buf(struct nexus_key * key, uint8_t * dst_buf, size_t dst_size)
{
    size_t    key_len = __vol_key_bytes(key);
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

    memcpy(tgt_buf, key->key, key_len);

    return tgt_buf;
}

static int
__vol_key_from_buf(struct nexus_key * key, uint8_t * src_buf, size_t src_size)
{
    uint32_t key_len = src_size;

    struct __volkey  * vkey = NULL;

    vkey = __alloc_volkey(key_len);

    memcpy(vkey->data, src_buf, key_len);

    key->key = vkey;

    return 0;
}


static char *
__vol_key_to_str(struct nexus_key * key)
{
    struct __volkey * volkey  = (struct __volkey *)(key->key);

    char *   key_str = NULL;
    uint32_t key_len = __vol_key_bytes(key);

    assert(key_len > 0);

    key_str = nexus_base64_encode((uint8_t *)volkey->data, key_len);

    return key_str;
}

static int
__vol_key_from_str(struct nexus_key * key, char * key_str)
{
    struct __volkey * volkey  = NULL;

    volkey = nexus_malloc(sizeof(struct __volkey));

    int ret = 0;

    ret = nexus_base64_decode(key_str, (uint8_t **)&(volkey->data), (uint32_t *)&volkey->len);

    if (ret == -1) {
        log_error("Could not decode raw key from base64\n");
        return -1;
    }

    key->key = volkey;

    return 0;
}

