/**
 * Copyright (c) 2018 - Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <nexus_list.h>
#include <nexus_mac.h>


struct nexus_metadata;


struct nexus_filenode {
    struct nexus_uuid          my_uuid;
    struct nexus_uuid          root_uuid;
    struct nexus_uuid          parent_uuid;

    struct nexus_uuid          link_uuid; // link UUID, changes on renames

    uint32_t                   chunksize;
    uint32_t                   log2chunksize;


    size_t                     link_count;

    uint32_t                   nchunks;
    uint64_t                   filesize;

    nexus_io_flags_t            mode;

    struct nexus_list          chunk_list;

    struct nexus_metadata    * metadata;
};


void
filenode_set_parent(struct nexus_filenode * filenode, struct nexus_uuid * parent_uuid);

/**
 * Creates a new filenode with a given root_uuid
 * @param root_uuid
 * @param my_uuid
 * @return filenode
 */
struct nexus_filenode *
filenode_create(struct nexus_uuid * root_uuid, struct nexus_uuid * my_uuid);

/**
 * loads the filenode
 * @param uuid
 * @return
 */
struct nexus_filenode *
filenode_load(struct nexus_uuid * uuid, nexus_io_flags_t flags);

struct nexus_filenode *
filenode_from_crypto_buf(struct nexus_crypto_buf * crypto_buf, nexus_io_flags_t flags);

int
filenode_store(struct nexus_uuid     * uuid,
               struct nexus_filenode * filenode,
               uint32_t                version,
               struct nexus_mac      * mac);

/**
 * Frees an allocated filenode
 * @param filenode
 */
void
filenode_free(struct nexus_filenode * filenode);

/**
 * Sets the filesize of the filenode
 */
int
filenode_set_filesize(struct nexus_filenode * filenode, size_t filesize);

/**
 * Gets the chunk at the particular offset in the file
 * @param filenode
 * @param offset
 * @return nexus_crypto_ctx.
 */
// TODO change API to prevent misuse
struct nexus_crypto_ctx *
filenode_get_chunk(struct nexus_filenode * filenode, size_t offset);



// hardlink stuff

void
filenode_incr_linkcount(struct nexus_filenode * filenode);

void
filenode_decr_linkcount(struct nexus_filenode * filenode);

size_t
filenode_get_linkcount(struct nexus_filenode * filenode);
