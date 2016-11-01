#pragma once
#include <stdint.h>
#ifndef UCPRIV_ENCLAVE
#include <uuid/uuid.h>
#else
typedef struct {
    uint8_t bin[16];
} uuid_t;
#endif
#include "ucafs_defs.h"

#define GLOBAL_MAGIC 0x20160811

#define CRYPTO_AES_KEY_SIZE 16
#define CRYPTO_AES_KEY_SIZE_BITS CRYPTO_AES_KEY_SIZE << 3
#define CRYPTO_CRYPTO_BLK_SIZE 16
#define CRYPTO_MAC_KEY_SIZE 16
#define CRYPTO_MAC_KEY_SIZE_BITS 16
#define CRYPTO_MAC_DIGEST_SIZE 32

#define CRYPTO_CEIL_TO_BLKSIZE(x)                                              \
    x + (CRYPTO_CRYPTO_BLK_SIZE - x % CRYPTO_CRYPTO_BLK_SIZE)

#define DEFAULT_REPO_DIRNAME ".afsx"
#define DEFAULT_DNODE_FNAME "main.dnode"

typedef enum {
    E_SUCCESS = 0,
    E_ERROR_ERROR,
    E_ERROR_CRYPTO,
    E_ERROR_ALLOC,
    E_ERROR_KEYINIT,
    E_ERROR_HASHMAP
} enclave_error_t;

typedef struct {
    int xfer_id;
    int enclave_crypto_id;
    int seg_id;
    uc_crypto_op_t op;
    char * buffer;
    uint32_t buflen;
    uint32_t valid_buflen; // how much "good" data can be read from the buffer
    uint32_t completed;
    int32_t position;
    uint32_t total_len;
    char * path;
} xfer_context_t;

typedef struct {
    uint8_t bytes[16];
} crypto_iv_t;

typedef struct {
    uint8_t ekey[CRYPTO_AES_KEY_SIZE];
} crypto_ekey_t;

typedef struct {
    uint8_t bytes[CRYPTO_MAC_DIGEST_SIZE];
} crypto_mac_t;

typedef struct {
#ifdef __cplusplus
    uint8_t raw[];
#endif
} raw_fname_t;

/* 128 bits */
typedef struct {
    uuid_t bin;
} encoded_fname_t;

typedef struct {
    uint16_t total_len; /* sizeof(struct) + strlen(target_link) */
    uint8_t type; /* 0 for soft, 1 for hard */
    uint8_t is_file;
    // TODO change this to a union
    encoded_fname_t meta_file;
    char target_link[];
} __attribute__((packed)) link_info_t;

typedef struct {
    crypto_ekey_t ekey;
    crypto_ekey_t mkey;
    crypto_iv_t iv;
    crypto_mac_t mac;
} __attribute__((packed)) crypto_context_t;

typedef struct {
    encoded_fname_t uuid;
    encoded_fname_t parent;
    uint8_t is_root;
    uint32_t count;
    uint32_t protolen;
    crypto_context_t crypto_ctx;
} __attribute__((packed)) dnode_header_t;

typedef struct {
    uint16_t link_count;
    uuid_t uuid;
    uint32_t chunk_count;
    uint32_t filelen;
    uint32_t protolen;
    crypto_context_t crypto_ctx;
} __attribute__((packed)) fbox_header_t;
