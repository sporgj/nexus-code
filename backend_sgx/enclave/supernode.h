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

struct nexus_metadata;


struct nexus_supernode {
    struct nexus_uuid          my_uuid;
    struct nexus_uuid          root_uuid;

    // the user table will be stored in a separate metadata file
    struct nexus_uuid          usertable_uuid;
    struct nexus_mac           usertable_mac;

    uint32_t                   hardlink_count;
    struct nexus_list          hardlink_table;

    struct nexus_metadata    * metadata;

    struct nexus_usertable   * usertable;
};


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


struct nexus_uuid *
supernode_get_reallink(struct nexus_supernode  * supernode, struct nexus_uuid * link_uuid);

int
supernode_add_hardlink(struct nexus_supernode  * supernode,
                       struct nexus_uuid       * src_uuid,
                       struct nexus_uuid       * dst_uuid);

bool
supernode_del_hardlink(struct nexus_supernode  * supernode,
                       struct nexus_uuid       * link_uuid,
                       struct nexus_uuid      ** real_uuid);

/**
 * renames all hardlinks with the said UUID
 * @param supernode
 * @param old_uuid
 * @param new_uuid
 * @param is_real_file if whether a "real" file has been renamed
 * @return true if any renaming occured
 */
bool
supernode_rename_link(struct nexus_supernode   * supernode,
                      struct nexus_uuid        * old_uuid,
                      struct nexus_uuid        * new_uuid,
                      bool                     * is_real_file);
