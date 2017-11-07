#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

/**
 * Signs a blob
 * @param pk the private key
 * @param data what to sign
 * @param len length of the input data
 * @param signature destination pointer for signature
 * @param signature_len destination pointer for signature len
 */
int
util_generate_signature(mbedtls_pk_context * pk,
                        uint8_t *            data,
                        size_t               len,
                        uint8_t **           signature,
                        size_t *             signature_len);

#define nexus_free(ptr) {       \
        free(ptr);              \
        ptr = NULL;             \
}

#ifdef __cplusplus
}
#endif
