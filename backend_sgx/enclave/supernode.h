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
#include "abac/nexus_abac.h"

#include "sgx_backend_common.h"

struct nexus_metadata;


struct nexus_supernode {
    struct nexus_uuid          my_uuid;
    struct nexus_uuid          root_uuid;

    // the user table will be stored in a separate metadata file
    struct nexus_uuid          usertable_uuid;
    struct nexus_mac           usertable_mac;

    struct nexus_uuid          hardlink_table_uuid;

    struct abac_superinfo      abac_superinfo;

    struct nexus_mac           mac;

    struct nexus_metadata    * metadata;

    struct nexus_usertable   * usertable;
};

void
__supernode_set_clean(struct nexus_supernode * supernode);

void
__supernode_set_dirty(struct nexus_supernode * supernode);

/**
 * Reads crypto_buffer
 * @param crypto_buffer
 * @return NULL on failure
 */
struct nexus_supernode *
supernode_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer, nexus_io_flags_t mode);

/**
 * Loads a supernode from UUID
 * @param uuid
 * @return supernode
 */
struct nexus_supernode *
supernode_load(struct nexus_uuid * uuid, nexus_io_flags_t mode);

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
 * @param version
 * @param mac
 * @return 0 on success
 */
int
supernode_store(struct nexus_supernode * supernode, int version, struct nexus_mac * mac);

void
supernode_free(struct nexus_supernode * supernode);
