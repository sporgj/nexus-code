#pragma once
#include <stdint.h>
#include <uuid/uuid.h>
#include <common.h>

#define CRYPTO_AES_IV_SIZE 16
#define CRYPTO_AES_KEY_SIZE 16
#define CRYPTO_AES_KEY_SIZE_BITS CRYPTO_AES_KEY_SIZE << 3
#define CRYPTO_CRYPTO_BLK_SIZE 16
#define CRYPTO_HMAC_SIZE 32

#define CRYPTO_GET_BLK_LEN(x)                                                      \
    x + (CRYPTO_CRYPTO_BLK_SIZE - x % CRYPTO_CRYPTO_BLK_SIZE);

typedef struct { uint8_t iv[CRYPTO_AES_IV_SIZE]; } crypto_iv_t;

typedef struct { uint8_t ekey[CRYPTO_AES_KEY_SIZE]; } crypto_ekey_t;

typedef struct { uint8_t mac[CRYPTO_HMAC_SIZE]; } crypto_mac_t;

typedef struct {
    uint32_t len;    // contains length of fname->data
    uint8_t data[0]; // gcc extensions :)
} raw_fname_t;

/* 128 bits */
typedef struct { uuid_t bin; } encoded_fname_t;
