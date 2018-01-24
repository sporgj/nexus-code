#pragma once

#include <stdint.h>

#include "sgx_backend_common.h"

#include "nexus_mac.h"

// represents an encrypted metadata object
struct nexus_crypto_buf;

/**
 * allocates a new crypto buffer with specified untrusted address and size
 * @param untrusted_addr
 * @param untrusted_size
 *
 * @return nexus_crypto_buf
 */
struct nexus_crypto_buf *
nexus_crypto_buf_create(struct nexus_uuid * uuid);

/**
 * Creates a new crypto buffer which will encrypt a metadata buffer of size.
 *
 * @param size
 * @return crypto_buf
 */
struct nexus_crypto_buf *
nexus_crypto_buf_new(size_t size);

void
nexus_crypto_buf_free(struct nexus_crypto_buf * buf);


/**
 * Returns a pointer to trusted memory containing the buffer's data
 *    Will decrypt existing data if it exists.
 * @param nexus_crypto_buf
 * @return NULL on failure
 */
void *
nexus_crypto_buf_get(struct nexus_crypto_buf * buf,
                     struct nexus_mac        * mac);


int
nexus_crypto_buf_put(struct nexus_crypto_buf * buf,
                     struct nexus_mac        * mac);

/**
 * Writes the encrypted contents of the crypto buf into the buffer
 * @param buf
 * @param metadata_uuid
 * @param uuid_path
 *
 * @return 0 on success
 */
int
nexus_crypto_buf_flush(struct nexus_crypto_buf * buf,
                       struct nexus_uuid       * metadata_uuid,
                       struct nexus_uuid_path  * uuid_path);

