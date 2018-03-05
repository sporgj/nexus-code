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

struct nexus_filenode {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t chunksize;
    uint32_t log2chunksize;

    uint32_t nchunks;
    uint64_t filesize;

    struct nexus_list chunk_list;
};


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
filenode_load(struct nexus_uuid * uuid);

int
filenode_store(struct nexus_filenode * filenode, struct nexus_mac * mac);

struct nexus_filenode *
filenode_from_buffer(uint8_t * buffer, size_t buflen);

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
struct nexus_crypto_ctx *
filenode_get_chunk(struct nexus_filenode * filenode, size_t offset);
