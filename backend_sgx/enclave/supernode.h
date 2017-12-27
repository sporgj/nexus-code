/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include "crypto.h"

#include "nexus_uuid.h"
#include "nexus_key.h"


struct supernode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;
    struct nexus_uuid user_list_uuid;

    uint8_t owner_pubkey[CRYPTO_HASH_BYTES];
};


/**
 * Instantiates a new supernode and generates both its uuid and the root uuid
 * @param user_pubkey is the user's public key
 * @return NULL on failure
 */
struct supernode *
supernode_create(struct nexus_raw_key * user_pubkey);

/**
 * Writes the supernode to the backing store
 * @param supernode
 * @return 0 on success
 */
int
supernode_store(struct supernode * supernode);

void
supernode_free(struct supernode * supernode);
