/**
 * Copyright (c) Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software. You are permitted to use, redistribute, and modify it
 * as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include "nexus_uuid.h"
#include "sgx_backend_common.h"

struct metadata_header {
    uint32_t version;

    uint32_t encrypted_buffer_size;

    struct nexus_uuid my_uuid;
} __attribute__((packed));


// contains the raw buffer written to disk
struct metadata_buffer {
    struct crypto_context crypto_context;

    // used for integrity checking
    struct metadata_header header;

    uint8_t encrypted_buffer[0];
} __attribute__((packed));


struct metadata {
    bool is_modified;

    struct nexus_uuid my_uuid;

    struct metadata_buffer metadata_buffer;
};


/**
 * Creates a new metadata with the following uuid
 * @param uuid
 */
struct metadata *
metadata_new(struct nexus_uuid * uuid);

/**
 * Reads the metadata from untrusted memory and decrypts it into the
 * internal_ptr
 * 
 * @param uuid is the uuid the user wishes to read
 * @param uuid_path NULL if there's no parent directory
 * @param decrypted_metadata_content
 * @param mac [optional] for a mac of the plaintext
 *
 * @return NULL on failure
 */
struct metadata *
metadata_open(struct nexus_uuid       * uuid,
              struct nexus_uuid_path  * uuid_path,
              void                   ** decrypted_metadata_content,
              crypto_mac_t            * mac);

/**
 * Writes the buffer to output memory.
 * On success, do NOT FREE buffer (used for caching).
 *
 * @param metadata the metadata to write to
 * @param buffer is the new contents of the metadata.
 * @param buflen
 *
 * @return 0 on success
 */
int
metadata_write(struct metadata * metadata,
               void            * metadata_content,
               size_t            buflen,
               crypto_mac_t    * mac);

/**
 * Frees the resources of the metadata object
 */
void
metadata_close(struct metadata * metadata);
