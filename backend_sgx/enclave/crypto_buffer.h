#pragma once

#include <stdint.h>

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
nexus_crypto_buf_create(void * untrusted_addr, size_t untrusted_size);

/**
 * Creates a new crypto buffer which will encrypt a metadata buffer of size.
 * This will cause the crypto buf to allocate data in untrusted memory.
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
                     uint8_t                 * trusted_buf,
                     struct nexus_mac        * mac);
