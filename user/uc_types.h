#pragma once
#include <stdint.h>
#include "ucafs_defs.h"

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
    int fbox_xfer;
    uc_fbox_t * fbox;
} xfer_context_t;

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

struct uc_dentry;
