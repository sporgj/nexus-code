/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once
#include "sgx_backend_common.h"

#include "acl.h"

#include <nexus_fs.h>
#include <nexus_uuid.h>
#include <nexus_list.h>

struct nexus_dirnode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t dir_entry_count;
    uint32_t dir_entry_buflen;

    struct nexus_acl dir_acl;

    struct nexus_list dir_entry_list;
};

/**
 * Creates a new dirnode
 *
 * @param root_uuid
 * @param my_uuid
 * @return NULL on failure
 */
struct nexus_dirnode *
dirnode_create(struct nexus_uuid * root_uuid, struct nexus_uuid * my_uuid);

/**
 * Loads the dirnode at specified address
 * @param uuid
 * @return
 */
struct nexus_dirnode *
dirnode_load(struct nexus_uuid * uuid);

/**
 * Writes dirnode to datastore
 *
 * @param dirnode
 * @param mac
 * @return 0 on success
 */
int
dirnode_store(struct nexus_dirnode * dirnode, struct nexus_mac * mac);

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

/**
 * adds a new directory entry to the dirnode
 *
 * @param dirnode
 * @param filename
 * @param type
 * @param entry_uuid will contain the UUID of the new entry
 * @return 0 on success
 */
int
dirnode_add(struct nexus_dirnode * dirnode,
            char                 * filename,
            nexus_dirent_type_t    type,
            struct nexus_uuid    * entry_uuid);

int
dirnode_find_by_uuid(struct nexus_dirnode * dirnode,
                     struct nexus_uuid    * uuid,
                     nexus_dirent_type_t  * p_type,
                     const char          ** p_fname,
                     size_t               * p_fname_len);

int
dirnode_find_by_name(struct nexus_dirnode * dirnode,
                     char                 * filename,
                     nexus_dirent_type_t  * type,
                     struct nexus_uuid    * entry_uuid);

int
dirnode_remove(struct nexus_dirnode * dirnode,
               char                 * filename,
               nexus_dirent_type_t  * type,
               struct nexus_uuid    * entry_uuid);
