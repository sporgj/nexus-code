#pragma once
#include <stdint.h>
#ifndef UCPRIV_ENCLAVE
#include <uuid/uuid.h>
#else
typedef struct { uint8_t bin[128]; } uuid_t;
#endif
#include "afsx_hdr.h"

#define GLOBAL_MAGIC 0x20160811

#define CRYPTO_AES_IV_SIZE 16
#define CRYPTO_AES_KEY_SIZE 16
#define CRYPTO_MAC_KEY_SIZE 16
#define CRYPTO_AES_KEY_SIZE_BITS CRYPTO_AES_KEY_SIZE << 3
#define CRYPTO_MAC_KEY_SIZE_BITS CRYPTO_MAC_KEY_SIZE << 3
#define CRYPTO_CRYPTO_BLK_SIZE 16
#define CRYPTO_HMAC_SIZE 32

#define CRYPTO_CEIL_TO_BLKSIZE(x)                                                      \
    x + (CRYPTO_CRYPTO_BLK_SIZE - x % CRYPTO_CRYPTO_BLK_SIZE);

#define DEFAULT_REPO_DIRNAME ".afsx"
#define DEFAULT_DNODE_FNAME "main.dnode"

typedef enum {
    UCPRIV_ENCRYPT = UCAFS_WRITEOP,
    UCPRIV_DECRYPT = UCAFS_READOP
} crypto_op_t;

typedef enum {
    E_SUCCESS = 0,
    E_ERROR_ERROR,
    E_ERROR_CRYPTO,
    E_ERROR_ALLOC,
    E_ERROR_KEYINIT,
    E_ERROR_HASHMAP
} enclave_error_t;

typedef struct {
    int op;
    int crypto_id;
    uint32_t seg_id;
    uint32_t id;
    char * buffer;
    uint32_t done;
    uint32_t len;
    uint32_t cap;
    uint64_t total;
    char * path;
} fop_ctx_t;

typedef struct { uint8_t iv[CRYPTO_AES_IV_SIZE]; } crypto_iv_t;

typedef struct { uint8_t ekey[CRYPTO_AES_KEY_SIZE]; } crypto_ekey_t;

typedef struct { uint8_t mac[CRYPTO_HMAC_SIZE]; } crypto_mac_t;

typedef struct {
#ifdef __cplusplus
    uint8_t raw[];
#endif
} raw_fname_t;

/* 128 bits */
typedef struct { uuid_t bin; } encoded_fname_t;

typedef struct {
    crypto_ekey_t ekey;
    crypto_ekey_t skey;
    crypto_mac_t mac;
    crypto_iv_t iv;
} __attribute__((packed)) file_crypto_t;

typedef struct {
    uint32_t magic;
    uint32_t count;
    uint32_t len;
    crypto_iv_t iv;
    crypto_ekey_t ekey;
    crypto_mac_t mac;
} __attribute__((packed)) dnode_header_t;

typedef struct {
    uint32_t seg_count; // number of segments in the file
    uint32_t flen;
    uint32_t plen; // length of the protocol buffer
    file_crypto_t crypto; // crypto protecting the whole protocol buffer file
} __attribute__((packed)) fbox_header_t;
