/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <nexus_uuid.h>
#include "sgx_backend_common.h"

struct dirnode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t dir_count; // number of files & subdirs
    uint32_t dirbuf_size;
};


/**
 * Creates a new dirnode
 *
 * @param root_uuid
 * @return NULL on failure
 */
struct dirnode *
dirnode_create(struct nexus_uuid * root_uuid);

/**
 * Writes dirnode to datastore
 *
 * @param dirnode
 * @param uuid_path
 * @param mac
 * @return 0 on success
 */
int
dirnode_store(struct dirnode         * dirnode,
              struct nexus_uuid_path * uuid_path,
              struct nexus_mac       * mac);

void
dirnode_free(struct dirnode * dirnode);
