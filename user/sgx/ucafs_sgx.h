#pragma once

#include <string.h>
#include <stdbool.h>

#include "enclave_t.h"

#include "../uc_types.h"

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

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

#define HMAC_TYPE mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)

#ifdef __cplusplus
extern "C" {
#endif

extern sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;
extern crypto_ekey_t * __enclave_key__;

extern bool enclave_is_logged_in, is_admin_program_running;

extern auth_struct_t enclave_auth_data;

extern supernode_t user_supernode, init_supernode;

extern pubkey_t * user_pubkey;

int
enclave_crypto_ekey(crypto_ekey_t * ekey,
                    crypto_ekey_t * sealing_key,
                    uc_crypto_op_t op);

struct snode_entry {
    SLIST_ENTRY(snode_entry) next_entry;
    supernode_t super;
    int len;
    char username[0]; // the username he is known to be
};

extern SLIST_HEAD(snode_head, snode_entry) supernode_list_head;
typedef struct snode_head snode_head_t;
typedef struct snode_entry snode_entry_t;

supernode_t * find_supernode(shadow_t * root_dnode);

crypto_ekey_t *
derive_skey(shadow_t * shdw1, shadow_t * shdw2);

#ifdef __cplusplus
}
#endif
