#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define CONFIG_UUID_BYTES 16

// the size of nonces in NEXUS
#define CONFIG_NONCE_BYTES  64

// for now, let's stick with GCM
// clang-format off
#define CONFIG_EKEY_BYTES   16
#define CONFIG_EKEY_BITS   (CONFIG_EKEY_BYTES << 3)
#define CONFIG_IV_BYTES     16
#define CONFIG_TAG_BYTES    16
#define CONFIG_HASH_BYTES   32 // sha256
// clang-format on

/* filesystem object types */
/* JRL: What is an ANY object? */
typedef enum {
    NEXUS_ANY  = 0,
    NEXUS_FILE = 1,
    NEXUS_DIR  = 2,
    NEXUS_LINK = 3
} nexus_fs_obj_type_t;

typedef uint8_t nonce_t[CONFIG_NONCE_BYTES];

typedef struct crypto_ekey {
    uint8_t bytes[CONFIG_EKEY_BYTES];
} crypto_ekey_t;

// TODO for now sealing is just ECB(rootkey). Investigate SGX sealing
struct volumekey {
    uint8_t bytes[CONFIG_EKEY_BYTES];
};

struct uuid {
    uint8_t bytes[CONFIG_UUID_BYTES];
};

struct crypto_context {
    crypto_ekey_t ekey;
    uint8_t       iv[CONFIG_IV_BYTES];
    uint8_t       tag[CONFIG_TAG_BYTES];
    uint8_t       ekey_mac[CONFIG_EKEY_BYTES];
};

// supernode structures. Manages the NeXUS volume
struct pubkey_hash {
    uint8_t bytes[CONFIG_HASH_BYTES];
};

struct user_entry {
    struct pubkey_hash pubkey;
    uint16_t namelen;
    uint8_t  name[0];
};

struct volume_user_table {
    uint32_t          user_count;
    uint32_t          user_buflen;
    struct user_entry user_list[0];
};

struct supernode_header {
    struct uuid              uuid;
    struct uuid              root_uuid;
    uint32_t                 total_size;
    struct pubkey_hash       owner;
} __attribute__((packed));

struct supernode {
    struct crypto_context    crypto_context;
    struct supernode_header  header;
    struct volume_user_table user_table;
} __attribute__((packed));

// -- dirnode stuff. Manages directories
struct dirnode_header {
    struct uuid uuid;
    struct uuid root_uuid;
    uint32_t    total_size;
    uint32_t    dir_count; // number of files and subdirectories
} __attribute__((packed));

struct dirnode_entry {
    nexus_fs_obj_type_t type;
    struct uuid         random_name;
    uint16_t            entry_len;
    uint16_t            name_len;
    char                real_name[0];
};

struct dirnode {
    struct crypto_context crypto_context;
    struct dirnode_header header;
    struct dirnode_entry  entries[0];
} __attribute__((packed));

// TODO
struct filenode {
    struct crypto_context crypto_context;
    uint32_t              total_size;
    struct uuid           uuid;
    struct uuid           root_uuid;
} __attribute__((packed));

#ifdef __cplusplus
}
#endif
