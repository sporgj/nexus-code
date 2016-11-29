#pragma once

#if defined(UCPRIV_ENCLAVE) || defined(KERNEL)
typedef struct {
    uint8_t bin[16];
} uuid_t;
#else
#include <uuid/uuid.h>
#endif

#ifdef KERNEL
#include "ucafs_gens.h"
#endif

#define AFSX_SERVER_PORT       9462
#define AFSX_SERVICE_PORT      0
#define AFSX_SERVICE_ID        4

#define AFSX_STATUS_SUCCESS        0
#define AFSX_STATUS_ERROR          1
#define AFSX_STATUS_NOOP           2

#define AFSX_PACKET_SIZE   4096

#define AFSX_FNAME_MAX         256
#define AFSX_PATH_MAX       1024

#ifdef UCAFS_DEV
#define UC_AFS_PATH_KERN    "/xyz.vm/user/djoko"
#define UC_AFS_PATH         "/afs" UC_AFS_PATH_KERN
#else
#define UC_AFS_PATH_KERN    "/maatta.sgx/user/bruyne"
#define UC_AFS_PATH         "/afs" UC_AFS_PATH_KERN
#endif

#define UC_AFS_WATCH    "sgx"

/* prefixes for the different file types */
#define UC_METADATA_PREFIX "md"
#define UC_FILEDATA_PREFIX "fd" 
#define UC_PREFIX_LEN(x) sizeof(x) - 1

#define UC_ENCRYPT    0x00000001
#define UC_DECRYPT    0x00000002
#define UC_VERIFY     0x00000004
typedef uint32_t uc_crypto_op_t;

#define UCAFS_STORE     UC_ENCRYPT
#define UCAFS_FETCH     UC_DECRYPT

#define UCAFS_DEFAULT_XFER_SIZE PAGE_SIZE
#define UCAFS_ALLOC_XFER_BUFFER __get_free_page(GFP_KERNEL)

#define UC_HARDLINK     0
#define UC_SOFTLINK     1

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

typedef enum {
    UC_FILE = 0x00000001,
    UC_DIR = 0x00000002,
    UC_LINK = 0x00000004,
    UC_ANY = UC_FILE | UC_DIR | UC_LINK,
} ucafs_entry_type;

typedef struct {
    crypto_ekey_t ekey;
    crypto_ekey_t mkey;
    crypto_iv_t iv;
    crypto_mac_t mac;
} __attribute__((packed)) crypto_context_t;

/* 128 bits */
typedef struct {
    uuid_t bin;
} shadow_t;

#define UCAFS_FBOX_MAGIC 0xfb015213
typedef struct uc_fbox {
    uint32_t magic;
    shadow_t uuid;
    uint16_t chunk_count;
    uint32_t file_size;
    uint16_t fbox_len; /* offset to start reading the file data */
    crypto_context_t crypto_ctx;
} __attribute__((packed)) uc_fbox_t;
