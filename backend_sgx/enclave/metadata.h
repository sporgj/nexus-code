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


/**
 * Reads the metadata from untrusted memory and decrypts it into the
 * 
 * @param uuid is the uuid the user wishes to read
 * @param uuid_path
 *
 * @return NULL on failure
 */
struct raw_buffer *
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
