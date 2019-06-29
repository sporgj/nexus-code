#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nexus_volume.h>
#include <nexus_uuid.h>
#include <nexus_key.h>
#include <nexus_fs.h>
#include <nexus_heap.h>
#include <nexus_ringbuf.h>

#define NONCE_SIZE 64


#define NEXUS_MAX_NAMELEN         25

#define NEXUS_PUBKEY_HASHLEN      32


#ifndef nx_crypto_box_PUBLICKEYBYTES
#define nx_crypto_box_PUBLICKEYBYTES 32
#endif

#ifndef nx_crypto_box_NONCEBYTES
#define nx_crypto_box_NONCEBYTES 24
#endif

// XXX this is temporary
#define NEXUS_CHUNK_SIZE_LOG    20
#define NEXUS_CHUNK_SIZE        (1 << NEXUS_CHUNK_SIZE_LOG)

#define NXS_ATTRIBUTE_NAME_MAX      32
#define NXS_ATTRIBUTE_VALUE_MAX     32


struct nonce_challenge {
    uint8_t bytes[NONCE_SIZE];
};


// used for the instance creation
struct ecdh_public_key {
    uint8_t  bytes[nx_crypto_box_PUBLICKEYBYTES];
} __attribute__((packed));

struct ecdh_nonce {
    uint8_t  bytes[nx_crypto_box_NONCEBYTES];
} __attribute__((packed));


// this will be used to transport keys across the enclave boundary
// @see keybuf.c and enclave/key_buffer.c
struct nexus_key_buffer {
    nexus_key_type_t key_type;

    size_t key_len;

    char * key_str;
};


struct nxs_user_buffer {
    char    name[NEXUS_MAX_NAMELEN];

    uint8_t pubkey_hash[NEXUS_PUBKEY_HASHLEN];
};


struct nxs_attribute_schema {
    char    schema_str[NXS_ATTRIBUTE_NAME_MAX];
    char    type_str[10]; // "user"|"object"
} __attribute__((packed));


struct nxs_attribute_pair {
    char    schema_str[NXS_ATTRIBUTE_NAME_MAX];
    char    val_str[NXS_ATTRIBUTE_VALUE_MAX];
};


struct nxs_policy_rule {
    size_t            total_len;
    struct nexus_uuid rule_uuid;
    char              rule_str[0];
} __attribute__((packed));


struct nxs_telemetry {
    size_t     lua_memory_kilobytes;

    size_t     total_allocated_bytes;

    size_t     asserted_facts_count;
    size_t     asserted_rules_count;
};
