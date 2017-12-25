#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>

#include "queue.h"

#include "nexus_enclave_t.h"

#define ocall_debug(str)                                                       \
    ocall_print("enclave> " str "\n")

#define my_free(x)                                                             \
    do {                                                                       \
        if (x != NULL) {                                                       \
            free(x);                                                           \
            x = NULL;                                                          \
        }                                                                      \
    } while (0)

extern sgx_key_128bit_t enclave_sealing_key;

struct dirnode_direntry_item {
    bool                      freeable; // if the direntry can be freed
    struct dirnode_direntry * direntry;
    TAILQ_ENTRY(dirnode_direntry_item) next_item;
};

struct dirnode_wrapper {
    bool              modified;
    struct dirnode *  dirnode;
    struct volumekey * volumekey;
    TAILQ_HEAD(dirnode_direntry_list, dirnode_direntry_item) direntry_head;
    TAILQ_ENTRY(dirnode_wrapper) next_item;
};

// cache of all stored dirnode wrapper items
extern size_t dirnode_cache_size;
extern TAILQ_HEAD(dirnode_wrapper_list, dirnode_wrapper) * dirnode_cache;


int
supernode_encryption(struct supernode *  supernode,
                     struct volumekey *  volumekey,
                     struct supernode ** p_sealed_supernode);

int
supernode_decryption(struct supernode *  sealed_supernode,
                     struct volumekey *  volumekey,
                     struct supernode ** p_supernode);

/**
 * Encrypts and seals a dirnode 
 * @param dirnode
 * @param dirnode_wrapper (can be null when no direntries are in the dirnode)
 * @param volumekey is the volumekey associated with the dirnode
 * @param p_sealed_dirnode is the destination dirnode
 */
int
dirnode_encryption(struct dirnode *         dirnode,
                   struct dirnode_wrapper * dirnode_wrapper,
                   struct volumekey *       volumekey,
                   struct dirnode **        p_sealed_dirnode);

int
dirnode_encryption_with_wrapper(struct dirnode_wrapper * dirnode_wrapper,
                                struct dirnode **        p_sealed_dirnode);

int
dirnode_decryption(struct dirnode *   sealed_dirnode,
                   struct volumekey * volumekey,
                   struct dirnode **  p_dirnode);

/**
 * Protects the volkey with the enclave sealing key before it is sent to
 * untrusted memory.
 */
int
volumekey_wrap(struct volumekey * volkey);

int
volumekey_unwrap(struct volumekey * volkey);

struct volumekey *
volumekey_from_rootuuid(struct nexus_uuid * root_uuid);

/* dirnode */

/**
 * Creates a new dirnode
 * @param uuid
 * @param root_uuid
 * @return NULL on FAILURE
 */
struct dirnode *
dirnode_new(struct nexus_uuid * uuid, struct nexus_uuid * root_uuid);

struct dirnode *
dirnode_copy(struct dirnode * dirnode);

void
dirnode_free(struct dirnode * dirnode);
