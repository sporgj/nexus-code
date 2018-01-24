/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include "../nexus_enclave_t.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

static char *
__mbedtls_pub_key_to_str(struct nexus_key * key)
{
    // TODO
    return NULL;
}

static char *
__mbedtls_prv_key_to_str(struct nexus_key * key)
{
    // TODO
    return NULL;
}

static int
__mbedtls_prv_key_from_str(struct nexus_key * key, char * key_str)
{
    mbedtls_pk_context * ctx = NULL;

    int ret = 0;

    ctx = calloc(sizeof(mbedtls_pk_context), 1);

    if (ctx == NULL) {
        return -1;
    }

    mbedtls_pk_init(ctx);

    /* Currently does not support password protected keys... */
    ret = mbedtls_pk_parse_key(
        ctx, (uint8_t *)key_str, strlen(key_str) + 1, NULL, 0);

    if (ret != 0) {
        goto err;
    }

    key->key = ctx;

    return 0;

err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);

    return -1;
}

static int
__mbedtls_pub_key_from_str(struct nexus_key * key, char * key_str)
{
    mbedtls_pk_context * ctx = NULL;

    int ret = 0;

    ctx = calloc(sizeof(mbedtls_pk_context), 1);

    if (ctx == NULL) {
        log_error("Could not allocate key context\n");
        return -1;
    }

    mbedtls_pk_init(ctx);

    ret = mbedtls_pk_parse_public_key(
        ctx, (uint8_t *)key_str, strlen(key_str) + 1);

    if (ret != 0) {
        log_error("Could not parse public key string\n");
        goto err;
    }

    key->key = ctx;

    return 0;

err:
    mbedtls_pk_free(ctx);
    nexus_free(ctx);

    return -1;
}

static int
__mbedtls_derive_pub_key(struct nexus_key * pub_key, struct nexus_key * prv_key)
{
    // TODO
    return -1;
}

static void
__mbedtls_free_key(struct nexus_key * key)
{
    mbedtls_pk_free(key->key);
    nexus_free(key->key);
}
