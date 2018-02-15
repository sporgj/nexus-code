/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once
#include <stdbool.h>

#include <nexus_uuid.h>
#include <sgx_backend_common.h>


typedef enum {
    NEXUS_DIRNODE,
    NEXUS_FILENODE
} nexus_metadata_type_t;

struct nexus_metadata {
    struct nexus_uuid uuid;

    uint32_t version;

    nexus_metadata_type_t type;

    bool is_dirty;

    union {
        struct nexus_dirnode  * dirnode;
        struct nexus_filenode * filenode;
    };
};


/**
 * Reads metadata content from untrusted memory and returns a crypto_buffer
 *
 * @param uuid is the uuid the user wishes to read
 * @param uuid_path
 *
 * @return NULL on failure
 */
struct nexus_crypto_buf *
metadata_read(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path);

/**
 * Writes an encrypted crypto buffer to the datastore
 *
 * @param uuid
 * @param uuid_path
 * @param crypto_buffer
 *
 * @return 0 on success
 */
int
metadata_write(struct nexus_uuid       * uuid,
               struct nexus_uuid_path  * uuid_path,
               struct nexus_crypto_buf * crypto_buffer);
