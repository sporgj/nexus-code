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
    int       len;
    uint8_t * data;
};

int
__vol_key_bytes(struct nexus_key * key)
{
    struct __volkey * vkey = (struct __volkey *)key->key;

    if (key->type == NEXUS_SEALED_VOLUME_KEY && vkey != NULL) {
	return vkey->len;
    }

    return -1;
}

uint8_t *
__vol_key_data(struct nexus_key * key)
{
    struct __volkey * vkey = (struct __volkey *)key->key;

    if (key->type == NEXUS_SEALED_VOLUME_KEY && vkey != NULL) {
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
__vol_key_create_key(struct nexus_key * key, uint8_t * data, int len)
{
    struct __volkey  * vkey = NULL;

    vkey = __alloc_volkey(len);

    memcpy(vkey->data, data, len);

    key->key  = vkey;
    key->type = NEXUS_SEALED_VOLUME_KEY;

    return 0;
}

struct nexus_key *
vol_key_create_key(uint8_t * data, int len)
{
    struct nexus_key * key  = NULL;

    key = nexus_malloc(sizeof(struct nexus_key));

    __vol_key_create_key(key, data, len);

    return key;
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

static char *
__vol_key_to_str(struct nexus_key * key)
{
    struct __volkey * volkey  = (struct __volkey *)(key->key);

    char *   key_str = NULL;
    uint32_t key_len = __vol_key_bytes(key);

    assert(key_len > 0);

    key_str = nexus_base64_encode(volkey->data, key_len);

    return key_str;
}

static int
__vol_key_from_str(struct nexus_key * key, char * key_str)
{
    struct __volkey * volkey  = (struct __volkey *)(key->key);

    int ret = 0;

    ret = nexus_base64_decode(key_str, (uint8_t **)&(volkey->data), (uint32_t *)&volkey->len);

    if (ret == -1) {
        log_error("Could not decode raw key from base64\n");
        return -1;
    }

    return 0;
}

static int
__vol_key_to_file(struct nexus_key * key, char * file_path)
{
    char * key_str = __vol_key_to_str(key);
    int    ret     = 0;

    ret = nexus_write_raw_file(file_path, key_str, strlen(key_str));

    if (ret == -1) {
        log_error("Could not write key file (%s)\n", file_path);
    }

    nexus_free(key_str);

    return ret;
}

static int
__vol_key_from_file(struct nexus_key * key, char * file_path)
{
    char * key_str = NULL;
    size_t key_len = 0;
    int    ret     = 0;

    ret = nexus_read_raw_file(file_path, (uint8_t **)&key_str, &key_len);

    if (ret == -1) {
        log_error("Could not read key file (%s)\n", file_path);
        return -1;
    }

    ret = __vol_key_from_str(key, key_str);

    if (ret == -1) {
        log_error("Could not convert raw key from string (%s)\n", key_str);
    }

    nexus_free(key_str);

    return ret;
}
