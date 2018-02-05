/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once
#include "sgx_backend_common.h"

#include <nexus_uuid.h>

#include <nexus_list.h>

typedef enum {
    NEXUS_FILE = 1,
    NEXUS_DIR  = 2,
    NEXUS_LINK = 3
} nexus_dirent_type_t;


struct nexus_dirnode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t dir_entry_count;
    uint32_t dir_entry_buflen;

    struct nexus_list dir_entry_list;
};

/**
 * Creates a new dirnode
 *
 * @param root_uuid
 * @return NULL on failure
 */
struct nexus_dirnode *
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
dirnode_store(struct nexus_dirnode   * dirnode,
              struct nexus_uuid_path * uuid_path,
              struct nexus_mac       * mac);

/**
 * Creates a nexus_dirnode from a buffer
 * @param buffer
 * @param buflen
 * @return dirnode
 */
struct nexus_dirnode *
dirnode_from_buffer(uint8_t * buffer, size_t buflen);

void
dirnode_free(struct nexus_dirnode * dirnode);
