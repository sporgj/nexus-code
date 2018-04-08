/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include "crypto.h"
#include "crypto_buffer.h"

#include <nexus_uuid.h>
#include <nexus_key.h>
#include <nexus_hash.h>

#include "user.h"

#include "sgx_backend_common.h"


struct nexus_supernode {
    uint32_t                   version;

    struct nexus_uuid          my_uuid;
    struct nexus_uuid          root_uuid;

    // the user table will be stored in a separate metadata file
    struct nexus_uuid          usertable_uuid;
    struct nexus_mac           usertable_mac;

    struct nexus_usertable   * usertable;
};


/**
 * Reads crypto_buffer
 * @param crypto_buffer
 * @return NULL on failure
 */
struct nexus_supernode *
supernode_from_crypto_buffer(struct nexus_crypto_buf * crypto_buffer);

/**
 * Loads a supernode from UUID
 * @param uuid
 * @return supernode
 */
struct nexus_supernode *
supernode_load(struct nexus_uuid * uuid);

/**
 * Instantiates a new supernode and generates both its uuid and the root uuid
 * @param user_pubkey is the user's public key
 * @param volumekey
 * @return NULL on failure
 */
struct nexus_supernode *
supernode_create(char * user_pubkey);

/**
 * Writes the supernode to the backing store
 * @param supernode
 * @return 0 on success
 */
int
supernode_store(struct nexus_supernode * supernode, struct nexus_mac * mac);

void
supernode_free(struct nexus_supernode * supernode);
