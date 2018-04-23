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

#include "libnexus_trusted/hashmap.h"

struct nexus_metadata;

struct nexus_dirnode {
    struct nexus_uuid       my_uuid;
    struct nexus_uuid       root_uuid;

    size_t                  symlink_count;
    size_t                  symlink_buflen;

    size_t                  dir_entry_count;
    size_t                  dir_entry_buflen;

    size_t                  bucket_count;

    nexus_io_flags_t        mode;


    struct nexus_acl        dir_acl;

    struct nexus_list       symlink_list;

    struct hashmap          filename_hashmap;
    struct hashmap          fileuuid_hashmap;

    struct nexus_list       bucket_list;

    struct nexus_metadata * metadata;
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
dirnode_load(struct nexus_uuid * uuid, nexus_io_flags_t flags);

struct nexus_dirnode *
dirnode_from_crypto_buf(struct nexus_crypto_buf * crypto_buf, nexus_io_flags_t flags);

/**
 * Writes dirnode to datastore
 *
 * FIXME
 * In some cases, the uuid from which a dirnode was read from is not equals to its
 * dirnode->my_uuid. This is usually the result of a rename operation (which does not
 * rewrite the dirnode of the moved directory). Explicitly specifying the uuid (stored
 * by the vfs) is a temporary solution.
 *
 * @param uuid: to write to.
 * @param dirnode
 * @param mac
 * @return 0 on success
 */
int
dirnode_store(struct   nexus_uuid    * uuid,
              struct   nexus_dirnode * dirnode,
              uint32_t                 version,
              struct   nexus_mac     * mac);

int
dirnode_compare(struct nexus_dirnode * src_dirnode, struct nexus_dirnode * dst_dirnode);

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
 * @param entry_uuid is the provided uuid
 * @return 0 on success
 */
int
dirnode_add(struct nexus_dirnode * dirnode,
            char                 * filename,
            nexus_dirent_type_t    type,
            struct nexus_uuid    * entry_uuid);

/**
 * adds a new link
 * @param dirnode
 * @param link_name
 * @param target_path
 * @param entry_uuid
 */
int
dirnode_add_link(struct nexus_dirnode * dirnode,
                 char                 * link_name,
                 char                 * target_path,
                 struct nexus_uuid    * entry_uuid);

/**
 * gets the target path pointed by the symlink
 * @param dirnode
 * @param entry_uuid
 * @return target_path
 */
char *
dirnode_get_link(struct nexus_dirnode * dirnode, struct nexus_uuid * entry_uuid);

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

/**
 * Removes an entry from the dirnode
 * @param dirnode
 * @param filanem
 * @param type. will contain the type of the entry
 * @param entry_uuid will contain the entry's uuid
 * @param symlink_target_path will contain the symlink path
 */
int
dirnode_remove(struct nexus_dirnode * dirnode,
               char                 * filename,
               nexus_dirent_type_t  * type,
               struct nexus_uuid    * entry_uuid,
               char                ** symlink_target_path);
