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


struct supernode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;
    struct nexus_uuid user_list_uuid;

    struct nexus_mac  volume_userlist_mac;

    struct nexus_hash owner_pubkey_hash;
};


struct supernode *
supernode_from_buffer(uint8_t * buffer, size_t buflen);

/**
 * Instantiates a new supernode and generates both its uuid and the root uuid
 * @param user_pubkey is the user's public key
 * @param volumekey
 * @return NULL on failure
 */
struct supernode *
supernode_create(char * user_pubkey);

/**
 * Writes the supernode to the backing store
 * @param supernode
 * @return 0 on success
 */
int
supernode_store(struct supernode       * supernode,
                struct nexus_uuid_path * uuid_path,
                struct nexus_mac       * mac);

void
supernode_free(struct supernode * supernode);
