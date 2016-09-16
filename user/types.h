#pragma once
#include <stdint.h>
#ifndef UCPRIV_ENCLAVE
#include <uuid/uuid.h>
#else
typedef struct { uint8_t bin[16]; } uuid_t;
#endif
#include "afsx_hdr.h"

#define GLOBAL_MAGIC 0x20160811

#define CRYPTO_AES_IV_SIZE 16
#define CRYPTO_AES_KEY_SIZE 16
#define CRYPTO_AES_KEY_SIZE_BITS CRYPTO_AES_KEY_SIZE << 3
#define CRYPTO_CRYPTO_BLK_SIZE 16
#define CRYPTO_GCMTAG_SIZE 16

#define CRYPTO_CEIL_TO_BLKSIZE(x)                                                      \
    x + (CRYPTO_CRYPTO_BLK_SIZE - x % CRYPTO_CRYPTO_BLK_SIZE)

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
    uint32_t buflen;
    uint32_t valid_buflen; // how much "good" data can be read from the buffer
    uint32_t completed;
    uint32_t raw_len;
    char * path;
} xfer_context_t;

typedef struct { uint8_t iv[CRYPTO_AES_IV_SIZE]; } crypto_iv_t;

typedef struct { uint8_t ekey[CRYPTO_AES_KEY_SIZE]; } crypto_ekey_t;

typedef struct { uint8_t tag[CRYPTO_GCMTAG_SIZE]; } crypto_tag_t;

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
    crypto_tag_t mac;
    crypto_iv_t iv;
} __attribute__((packed)) crypto_context_t;

typedef struct {
    uint32_t magic;
    uint32_t count;
    uint32_t len;
    crypto_iv_t iv;
    crypto_ekey_t ekey;
    crypto_tag_t mac;
} __attribute__((packed)) dnode_header_t;

typedef struct {
    uint32_t seg_count; // number of segments in the file
    uint32_t flen;
    uint32_t plen; // length of the protocol buffer
    crypto_context_t crypto; // crypto protecting the whole protocol buffer file
} __attribute__((packed)) fbox_header_t;
