/**
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <assert.h>

#include <nexus_encode.h>
#include <nexus_uuid.h>

#include <sgx_trts.h>

#include "./gcm-siv/GCM_SIV.h"

#include "../crypto.h"

/// the volume key will be used to "seal" (keywrapping, to be more precise)
extern struct nexus_key * global_volumekey;


struct __wrapped_keydata {
    uint8_t     tag[GCM128_TAG_SIZE];
    uint8_t     ekey[0];        // variable-length array to store key data
};

static inline int
__wrapped_key_bits(struct nexus_key * key)
{
    switch (key->type) {
    case NEXUS_WRAPPED_256_KEY:
        return (256);
    case NEXUS_WRAPPED_128_KEY:
        return (128);
    default:
        return -1;
    }

    return -1;
}

static inline int
__wrapped_key_bytes(struct nexus_key * key)
{
    switch (key->type) {
    case NEXUS_WRAPPED_256_KEY:
        return (256 / 8);
    case NEXUS_WRAPPED_128_KEY:
        return (128 / 8);
    default:
        return -1;
    }

    return -1;
}

static inline int
__wrapped_key_bufsize(struct nexus_key * key)
{
    return GCM128_TAG_SIZE + __wrapped_key_bytes(key);
}

static struct __wrapped_keydata *
__wrapped_key_alloc (struct nexus_key * raw_key)
{
    size_t key_size = __raw_key_bytes(raw_key);

    assert(key_size > 0);

    size_t total_len = key_size + sizeof(struct __wrapped_keydata);

    return nexus_malloc(total_len);
}

static int
__wrap_key(struct nexus_key * wrapped_key, struct nexus_key * raw_key)
{
    struct __wrapped_keydata * keydata = NULL;

    if (raw_key->uuid == NULL) {
        log_error("need associated uuid on key\n");
        return -1;
    }

    keydata = __wrapped_key_alloc(raw_key);

    {
        AES_GCM_SIV_CONTEXT gcm_siv;

        AES_GCM_SIV_Init(&gcm_siv, global_volumekey->key);

        AES_GCM_SIV_Encrypt(&gcm_siv,
                            keydata->ekey,
                            keydata->tag,
                            NULL,
                            raw_key->key,
                            0,
                            __raw_key_bytes(raw_key), // size of key to encrypt
                            raw_key->uuid->raw); // 16 bytes of UUID

        Clear_SIV_CTX(&gcm_siv);
    }

    wrapped_key->key = keydata;

    return 0;
}

static int
__unwrap_key(struct nexus_key * unwrapped_key, struct nexus_key * wrapped_key)
{
    struct __wrapped_keydata * keydata = wrapped_key->key;

    size_t    rawkey_size = 0;

    uint8_t * rawkey_key  = NULL;

    int       ret         = -1;


    if (wrapped_key->uuid == NULL) {
        log_error("need associated uuid on key\n");
        return -1;
    }


    rawkey_size = __wrapped_key_bytes(wrapped_key);

    assert(rawkey_size > 0);


    rawkey_key  = nexus_malloc(rawkey_size);


    {
        AES_GCM_SIV_CONTEXT gcm_siv;

        AES_GCM_SIV_Init(&gcm_siv, global_volumekey->key);

        ret = AES_GCM_SIV_Decrypt(&gcm_siv,
                                  rawkey_key,
                                  keydata->tag,
                                  NULL,
                                  keydata->ekey,
                                  0,
                                  rawkey_size,
                                  wrapped_key->uuid->raw);

        Clear_SIV_CTX(&gcm_siv);
    }

    if (ret) {
        nexus_free(rawkey_key);
        log_error("AES_GCM_SIV_Decrypt FAILED\n");
        return -1;
    }

    unwrapped_key->key = rawkey_key;

    return 0;
}

static int
__wrapped_copy_key(struct nexus_key * src_key, struct nexus_key * dst_key)
{
    uint32_t key_len = __wrapped_key_bufsize(src_key);

    assert(key_len > 0);

    dst_key->key = nexus_malloc(key_len);

    memcpy(dst_key->key, src_key->key, key_len);

    return 0;
}

static uint8_t *
__wrapped_key_to_buf(struct nexus_key * key, uint8_t * dst_buf, size_t dst_size)
{
    size_t    key_len = __wrapped_key_bufsize(key);
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
__wrapped_key_from_buf(struct nexus_key * key, uint8_t * src_buf, size_t src_size)
{
    size_t key_len = __wrapped_key_bufsize(key);

    if (key_len > src_size) {
        log_error("buffer is too small for wrapped key (min=%zu, act=%zu)\n", key_len, src_size);
        return -1;
    }

    // in case the key exists
    if (key->key) {
        nexus_free(key->key);
    }

    key->key = nexus_malloc(key_len);

    memcpy(key->key, src_buf, key_len);

    return 0;
}

static char *
__wrapped_key_to_str(struct nexus_key * key)
{
    char *   key_str = NULL;
    uint32_t key_len = __wrapped_key_bufsize(key);

    assert(key_len > 0);

    key_str = nexus_base64_encode(key->key, key_len);

    return key_str;
}

static int
__wrapped_key_from_str(struct nexus_key * key, char * key_str)
{
    uint32_t key_len = __wrapped_key_bufsize(key);
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
