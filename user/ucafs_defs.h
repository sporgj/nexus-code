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

#define AFSX_SERVER_PORT 9462
#define AFSX_SERVICE_PORT 0
#define AFSX_SERVICE_ID 4

#define AFSX_STATUS_SUCCESS 0
#define AFSX_STATUS_ERROR 1
#define AFSX_STATUS_NOOP 2

#define AFSX_PACKET_SIZE 4096

#define AFSX_FNAME_MAX 256
#define AFSX_PATH_MAX 1024

#ifdef UCAFS_DEV
#define UC_AFS_PATH_KERN "/xyz.vm/user/djoko"
#define UC_AFS_PATH "/afs" UC_AFS_PATH_KERN
#else
#define UC_AFS_PATH_KERN "/maatta.sgx/user/bruyne"
#define UC_AFS_PATH "/afs" UC_AFS_PATH_KERN
#endif

#define UC_AFS_WATCH "sgx"

/* prefixes for the different file types */
#define UC_METADATA_PREFIX "md"
#define UC_FILEDATA_PREFIX "fd"
#define UC_PREFIX_LEN(x) sizeof(x) - 1

#define UC_ENCRYPT 0x00000001
#define UC_DECRYPT 0x00000002
#define UC_VERIFY 0x00000004
typedef uint32_t uc_crypto_op_t;

#define UCAFS_STORE UC_ENCRYPT
#define UCAFS_FETCH UC_DECRYPT
typedef uint16_t uc_xfer_op_t; // UCAFS_FETCH/UCAFS_STORE

#define UC_HARDLINK 0
#define UC_SOFTLINK 1

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

#define UCAFS_FBOX_READ 0
#define UCAFS_FBOX_WRITE 1

#define UCAFS_CHUNK_LOG 20
#define UCAFS_CHUNK_SIZE (1 << UCAFS_CHUNK_LOG)

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
FBOX_CHUNK_BASE(int offset)
{
    return ((offset < afs_FirstCSize)
                ? 0
                : (((offset - afs_FirstCSize) & ~(afs_OtherCSize - 1))
                   + afs_FirstCSize));
}

static inline int
FBOX_CHUNK_NUM(int offset)
{
    return ((offset < UCAFS_CHUNK_SIZE)
                ? 0
                : 1 + ((offset - UCAFS_CHUNK_SIZE) >> UCAFS_CHUNK_LOG));
}

static inline int
FBOX_CHUNK_COUNT(int file_size)
{
    return FBOX_CHUNK_NUM(file_size) + 1;
}

static inline int
FBOX_SIZE(int file_size) {
    return sizeof(uc_fbox_header_t)
        + FBOX_CHUNK_COUNT(file_size) * sizeof(crypto_context_t);
}

static inline size_t
CHUNK_RATIO(int numerator_log, int denomintor_log)
{
    int ratio = numerator_log - denomintor_log;
    return ratio <= 0 ? 2 : (1 << ratio) + 1;
}
