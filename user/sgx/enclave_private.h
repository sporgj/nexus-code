#pragma once

#include <string.h>
#include <stdbool.h>

#include "enclave_t.h"

#include "../uc_types.h"

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>

#ifndef MIN
#define MIN(a,b) (a<b)?a:b
#endif

#ifndef MAX
#define MAX(a,b) (a>b)?a:b
#endif

/* data protection levels for enclave variable */
#define __TOPSECRET__ // resides in enclave, not erased
#define __SECRET // resides in enclave, gets erased
#define _CONFIDENTIAL // copyh in and out with care

#define E_CRYPTO_BUFFER_LEN 256

#ifdef __cplusplus
extern "C" {
#endif

extern sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;

extern bool enclave_is_logged_in;

extern struct enclave_auth enclave_auth_data;

int enclave_crypto_ekey(crypto_ekey_t * ekey, uc_crypto_op_t op);

int
crypto_metadata(crypto_context_t * p_ctx,
                size_t protolen,
                uint8_t * data,
                uc_crypto_op_t op);

#ifdef __cplusplus
}
#endif
