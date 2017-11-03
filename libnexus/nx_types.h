#pragma once
#include <stdint.h>

#include <uuid/uuid.h>

#include "nexus.h"

#ifdef __cplusplus
extern "C" {
#endif


#define CONFIG_UUID_BYTES 16

// for now, let's stick with GCM
// clang-format off
#define CONFIG_EKEY_BYTES   16
#define CONFIG_IV_BYTES     16
#define CONFIG_TAG_BYTES    16
// clang-format on

struct uuid {
    uint8_t bytes[CONFIG_UUID_BYTES];
};

struct crypto_context {
    uint8_t ekey[CONFIG_EKEY_BYTES];
    uint8_t iv[CONFIG_IV_BYTES];
    uint8_t tag[CONFIG_TAG_BYTES];
    uint8_t ekey_mac[CONFIG_EKEY_BYTES];
};

/* entries in the supernode user list */
struct user_entry {
    uint16_t namelen;
    uint16_t pubkeylen;
    uint8_t  name_and_pubkey[0];
};

struct supernode {
    struct uuid           uuid;
    struct uuid           root_uuid;
    struct crypto_context crypto_context;

    uint32_t          user_count;
    uint32_t          user_buflen;
    struct user_entry user_list[0];
} __attribute__((packed));

struct dirnode {
    struct uuid           uuid;
    struct uuid           root_uuid;
    struct crypto_context crypto_context;
} __attribute__((packed));

struct filenode {
    struct uuid           uuid;
    struct uuid           root_uuid;
    struct crypto_context crypto_context;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif
