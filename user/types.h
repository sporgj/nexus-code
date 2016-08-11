#pragma once
#include <stdint.h>
#include <uuid/uuid.h>
#include <common.h>

#define GLOBAL_MAGIC 0x20160811

#define CRYPTO_AES_IV_SIZE 16
#define CRYPTO_AES_KEY_SIZE 16
#define CRYPTO_AES_KEY_SIZE_BITS CRYPTO_AES_KEY_SIZE << 3
#define CRYPTO_CRYPTO_BLK_SIZE 16
#define CRYPTO_HMAC_SIZE 32

#define CRYPTO_CEIL_TO_BLKSIZE(x)                                                      \
    x + (CRYPTO_CRYPTO_BLK_SIZE - x % CRYPTO_CRYPTO_BLK_SIZE);

typedef enum {
    ENCRYPT = 0,
    DECRYPT = 1
} crypto_op_t;

typedef struct { uint8_t iv[CRYPTO_AES_IV_SIZE]; } crypto_iv_t;

typedef struct { uint8_t ekey[CRYPTO_AES_KEY_SIZE]; } crypto_ekey_t;

typedef struct { uint8_t mac[CRYPTO_HMAC_SIZE]; } crypto_mac_t;

typedef struct {
    uint8_t raw[];
} raw_fname_t;

/* 128 bits */
typedef struct { uuid_t bin; } encoded_fname_t;

typedef struct {
    uint32_t magic;
    uint32_t count;
    uint32_t len;
    crypto_iv_t iv;
    crypto_ekey_t ekey;
    crypto_mac_t mac;
} __attribute__((packed)) file_header_t;
