#pragma once
#include <stdint.h>
#include "ucafs_header.h"
#include <mbedtls/pk.h>

#define CRYPTO_CEIL_TO_BLKSIZE(x)                                              \
    x + (CRYPTO_CRYPTO_BLK_SIZE - x % CRYPTO_CRYPTO_BLK_SIZE)

#define UC_HARDLINK 0
#define UC_SOFTLINK 1

#define DEFAULT_REPO_DIRNAME ".afsx"
#define DEFAULT_DNODE_FNAME "main.dnode"

#define PUBKEY_HASH_LEN 256

struct uc_dentry;
struct filebox;
typedef struct filebox uc_filebox_t;

/* 128 bits */
typedef struct {
    uuid_t bin;
} shadow_t;

typedef enum {
    E_SUCCESS = 0,
    E_ERROR_ERROR,
    E_ERROR_CRYPTO,
    E_ERROR_ALLOC,
    E_ERROR_KEYINIT,
    E_ERROR_HASHMAP
} enclave_error_t;

typedef struct {
    uint8_t raw[0];
} raw_fname_t;

typedef struct {
    uint16_t total_len; /* sizeof(struct) + strlen(target_link) */
    uint8_t type; /* 0 for soft, 1 for hard */
    union {
        shadow_t meta_file;
        char target_link[0];
    };
} __attribute__((packed)) link_info_t;

/* cryptographic stuff */
#define CRYPTO_AES_KEY_SIZE 16
#define CRYPTO_AES_KEY_SIZE_BITS CRYPTO_AES_KEY_SIZE << 3
#define CRYPTO_CRYPTO_BLK_SIZE 16
#define CRYPTO_MAC_KEY_SIZE 16
#define CRYPTO_MAC_KEY_SIZE_BITS 16
#define CRYPTO_MAC_DIGEST_SIZE 32

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
    crypto_ekey_t ekey;
    crypto_ekey_t mkey;
    crypto_iv_t iv;
    crypto_mac_t mac;
} __attribute__((packed)) crypto_context_t;

/* File box information */
#define UCAFS_FBOX_MAGIC 0xfb015213
#define UCAFS_FBOX_HEADER                                                      \
    uint32_t magic;                                                            \
    uint8_t link_count;                                                        \
    uint16_t chunk_count;                                                      \
    uint32_t chunk_size;                                                       \
    uint32_t file_size;                                                        \
    uint16_t fbox_len;                                                         \
    uuid_t uuid;                                                               \
    crypto_ekey_t fbox_mkey;                                                   \
    crypto_mac_t fbox_mac;

typedef struct {
    UCAFS_FBOX_HEADER;
} __attribute__((packed)) uc_fbox_header_t;

typedef struct uc_fbox {
    UCAFS_FBOX_HEADER;
    crypto_context_t chunks[1];
} __attribute__((packed)) uc_fbox_t;

#define FBOX_HEADER_LEN sizeof(uc_fbox_header_t)
#define UCAFS_GET_REAL_FILE_SIZE(len) len - sizeof(uc_fbox_t)
#define FBOX_DEFAULT_LEN sizeof(uc_fbox_t)

static inline int
UCAFS_FBOX_SIZE(int file_size)
{
    return sizeof(uc_fbox_header_t)
        + UCAFS_CHUNK_COUNT(file_size) * sizeof(crypto_context_t);
}

typedef struct {
    int xfer_id;
    int enclave_crypto_id;
    int chunk_num; // chunk number for the current store
    uc_xfer_op_t xfer_op; // UCAFS_FETCH/UCAFS_STORE
    char * buffer;
    uint32_t buflen;
    uint32_t valid_buflen; // how much "good" data can be read from the buffer
    uint32_t completed;
    uint32_t offset;
    uint32_t total_len;
    char * path;
    int fbox_xfer;
    int fbox_rd;
    int fbox_wr;
    uc_fbox_t * fbox;
    uc_filebox_t * filebox;
} xfer_context_t;

typedef struct {
    shadow_t uuid;
    shadow_t parent;
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

#define SUPERNODE_HEADER \
    crypto_context_t crypto_ctx; \
    uint32_t count; \
    shadow_t root_dnode;

typedef struct {
    SUPERNODE_HEADER;
} __attribute__((packed)) supernode_header_t;

typedef struct {
    SUPERNODE_HEADER;
} __attribute__((packed)) supernode_t;

