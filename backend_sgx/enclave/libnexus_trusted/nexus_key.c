/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <stdlib.h>
#include <string.h>


#include "../enclave_internal.h"

#include "nexus_key_mbedtls.c"
#include "nexus_key_raw.c"
#include "nexus_key_wrapped.c"
#include "nexus_key_sealed_volkey.c"


void
nexus_free_key(struct nexus_key * key)
{
    if (key->uuid) {
        nexus_free(key->uuid);
    }

    switch (key->type) {
    case NEXUS_RAW_128_KEY:
    case NEXUS_RAW_256_KEY:
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
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
nexus_generate_key(struct nexus_key * key, nexus_key_type_t key_type)
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
        log_error("Could not create ke\ny");
        goto err;
    }

    return key;

err:
    nexus_free(key);
    return NULL;
}

int
nexus_key_set_uuid(struct nexus_key * key, struct nexus_uuid * uuid)
{
    if (key->uuid) {
        nexus_free(key->uuid);
    }

    key->uuid = nexus_uuid_clone(uuid);

    return key->uuid == NULL;
}

int
__nexus_derive_key(struct nexus_key * new_key,
                   nexus_key_type_t   key_type,
                   struct nexus_key * src_key)
{
    int ret = 0;

    nexus_init_key(new_key, key_type);

    switch (key_type) {
    case NEXUS_MBEDTLS_PRV_KEY:
        log_error("Private keys cannot be derived, they must be created\n");
        goto err;
    case NEXUS_MBEDTLS_PUB_KEY:
        ret = __mbedtls_derive_pub_key(new_key, src_key);
        break;
    case NEXUS_WRAPPED_128_KEY:
        if (src_key->type != NEXUS_RAW_128_KEY) {
            log_error("Error: Can only seal 128 bit RAW key as 128 bit SEALED key\n");
            goto err;
        }

        ret = __wrap_key(new_key, src_key);
        break;

    case NEXUS_WRAPPED_256_KEY:
        if (src_key->type != NEXUS_RAW_256_KEY) {
            log_error("Error: Can only seal 256 bit RAW key as 256 SEALED key\n");
            goto err;
        }

        ret = __wrap_key(new_key, src_key);
        break;
    case NEXUS_RAW_128_KEY:
        if (src_key->type != NEXUS_WRAPPED_128_KEY && src_key->type != NEXUS_SEALED_VOLUME_KEY) {
            log_error("Error: Can only unseal 128 bit SEALED key in to 128 RAW key\n");
            goto err;
        }

        if (src_key->type == NEXUS_WRAPPED_128_KEY) {
            ret = __unwrap_key(new_key, src_key);
        } else {
            // NEXUS_SEALED_VOLUME_KEY
            ret = __vol_key_unseal(new_key, src_key);
        }

        break;
    case NEXUS_RAW_256_KEY:
        if (src_key->type != NEXUS_WRAPPED_256_KEY && src_key->type != NEXUS_SEALED_VOLUME_KEY) {
            log_error("Error: Can only unseal 256 bit SEALED key in to 256 RAW key\n");
            goto err;
        }

        ret = __unwrap_key(new_key, src_key);

        if (src_key->type == NEXUS_WRAPPED_256_KEY) {
            ret = __unwrap_key(new_key, src_key);
        } else {
            // NEXUS_SEALED_VOLUME_KEY
            ret = __vol_key_unseal(new_key, src_key);
        }

        break;

    case NEXUS_SEALED_VOLUME_KEY:
	// even though it should work with other keys, we restrict it to raw keys for now
	if (src_key->type != NEXUS_RAW_128_KEY && src_key->type != NEXUS_RAW_256_KEY) {
            log_error("can only seal raw keys\n");
            goto err;
        }

	ret = __vol_key_seal(new_key, src_key);
	break;

    default:
        log_error("Invalid key type\n");
        goto err;
    }


    return ret;

 err:
    return -1;
}

struct nexus_key *
nexus_derive_key(nexus_key_type_t key_type, struct nexus_key * src_key)
{
    struct nexus_key * key = NULL;

    int ret = 0;

    key = nexus_malloc(sizeof(struct nexus_key));

    ret = __nexus_derive_key(key, key_type, src_key);

    if (ret == -1) {
        log_error("Could not create key\n");
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

    ret = nexus_copy_key(src_key, key);

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
nexus_copy_key(struct nexus_key * src_key, struct nexus_key * dst_key)
{
    int ret = 0;

    dst_key->type = src_key->type;

    switch (src_key->type) {
    case NEXUS_RAW_128_KEY:
    case NEXUS_RAW_256_KEY:
        ret = __raw_copy_key(src_key, dst_key);
        break;
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        ret = __wrapped_copy_key(src_key, dst_key);
        break;
    case NEXUS_SEALED_VOLUME_KEY:
	ret = __vol_key_copy_key(src_key, dst_key);
	break;
    case NEXUS_MBEDTLS_PUB_KEY:
    case NEXUS_MBEDTLS_PRV_KEY:
    default:
        log_error("Could not copy key for invalid key type\n");
        return -1;
    }

    return ret;
}

int
nexus_key_bytes(struct nexus_key * key)
{
    int ret = -1;

    switch (key->type) {
    case NEXUS_RAW_128_KEY:
    case NEXUS_RAW_256_KEY:
        ret = __raw_key_bytes(key);
        break;
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        ret = __wrapped_key_bytes(key);
        break;
    case NEXUS_SEALED_VOLUME_KEY:
	ret = __vol_key_bytes(key);
	break;
    default:
        log_error("could not get size for key type\n");
        return -1;
    }

    return ret;
}

int
nexus_key_bits(struct nexus_key * key)
{
    int ret = -1;

    switch (key->type) {
    case NEXUS_RAW_128_KEY:
    case NEXUS_RAW_256_KEY:
        ret = __raw_key_bits(key);
        break;
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        ret = __wrapped_key_bits(key);
        break;

    default:
        log_error("could not get size for key type\n");
        return -1;
    }

    return ret;
}



/* Return Value:
 *    NULL on error, otherwise a pointer to the buffer serialized into
 *    If dst_buf is NULL, then a new buffer is allocated
 */
uint8_t *
nexus_key_to_buf(struct nexus_key * key, uint8_t * dst_buf, size_t dst_size)
{
    uint8_t * buf = NULL;

    switch (key->type) {
    case NEXUS_RAW_128_KEY:
    case NEXUS_RAW_256_KEY:
        buf = __raw_key_to_buf(key, dst_buf, dst_size);
        break;
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        buf = __wrapped_key_to_buf(key, dst_buf, dst_size);
        break;
    case NEXUS_SEALED_VOLUME_KEY:
	buf = __vol_key_to_buf(key, dst_buf, dst_size);
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

    nexus_init_key(key, key_type);

    switch (key->type) {
    case NEXUS_RAW_128_KEY:
    case NEXUS_RAW_256_KEY:
        ret = __raw_key_from_buf(key, src_buf, src_buflen);
        break;
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        ret = __wrapped_key_from_buf(key, src_buf, src_buflen);
        break;
    case NEXUS_SEALED_VOLUME_KEY:
	ret = __vol_key_from_buf(key, src_buf, src_buflen);
	break;
    default:
        log_error("Cannot unserialize this key type (%s) from a buffer\n",
                  nexus_key_type_to_str(key->type));
        return -1;
    }

    return ret;
}

struct nexus_key *
nexus_key_from_buf(nexus_key_type_t key_type, uint8_t * src_buf, size_t src_size)
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
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        str = __wrapped_key_to_str(key);
        break;
    case NEXUS_SEALED_VOLUME_KEY:
        str = __vol_key_to_str(key);
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
__nexus_key_from_str(struct nexus_key * key, nexus_key_type_t key_type, char * key_str)
{
    int ret = 0;

    nexus_init_key(key, key_type);

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
    case NEXUS_WRAPPED_128_KEY:
    case NEXUS_WRAPPED_256_KEY:
        ret = __wrapped_key_from_str(key, key_str);
        break;
    case NEXUS_SEALED_VOLUME_KEY:
        ret = __vol_key_from_str(key, key_str);
        break;
    default:
        log_error("Invalid key type");
        return -1;
    }

    return ret;
}

struct nexus_key *
nexus_key_from_str(nexus_key_type_t key_type, char * key_str)
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

struct nexus_key_desc {
    nexus_key_type_t type;
    char *           desc;
};

struct nexus_key_desc nexus_key_descriptors[] = {
    { NEXUS_MBEDTLS_PUB_KEY, "NEXUS_MBEDTLS_PUB_KEY" },
    { NEXUS_MBEDTLS_PRV_KEY, "NEXUS_MBEDTLS_PRV_KEY" },
    { NEXUS_RAW_128_KEY, "NEXUS_RAW_128_KEY" },
    { NEXUS_RAW_256_KEY, "NEXUS_RAW_256_KEY" },
    { NEXUS_WRAPPED_128_KEY, "NEXUS_WRAPPED_128_KEY" },
    { NEXUS_WRAPPED_256_KEY, "NEXUS_WRAPPED_256_KEY" },
    { NEXUS_SEALED_VOLUME_KEY, "NEXUS_SEALED_VOLUME_KEY" },
    { NEXUS_INVALID_KEY, "NEXUS_INVALID_KEY_TYPE" }
};


char *
nexus_key_type_to_str(nexus_key_type_t type)
{
    size_t count = sizeof(nexus_key_descriptors) / sizeof(struct nexus_key_desc);

    for (size_t i = 0; i < count; i++) {
        if (type == nexus_key_descriptors[i].type) {
            return nexus_key_descriptors[i].desc;
        }
    }

    return "NEXUS_INVALID_KEY_TYPE";
}


nexus_key_type_t
nexus_key_type_from_str(char * type_str)
{
    size_t count = sizeof(nexus_key_descriptors) / sizeof(struct nexus_key_desc);

    for (size_t i = 0; i < count; i++) {
	char * desc = nexus_key_descriptors[i].desc;

	if (strncmp(type_str, desc, strlen(desc)) == 0) {
            return nexus_key_descriptors[i].type;
        }
    }

    return NEXUS_INVALID_KEY;
}
