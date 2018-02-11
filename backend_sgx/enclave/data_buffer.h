#pragma once

#include "crypto_context.h"

#include "libnexus_trusted/nexus_mac.h"

struct data_buffer;

/**
 * Creates a new data_buffer from an external address. A data buffer can only encrypt a
 * chunk at a time.
 *
 * @param external_addr
 * @param chunk_offset
 * @return chunk_size
 */
struct nexus_data_buffer *
nexus_data_buffer_create(uint8_t * external_addr, size_t chunk_offset, size_t chunk_size);

/**
 * Encrypts the data buffer in external memory
 * @param data_buffer
 * @param crypto_ctx_dest_ptr
 * @param mac
 */
int
nexus_data_buffer_put(struct nexus_data_buffer * data_buffer,
                      struct nexus_crypto_ctx  * crypto_ctx_dest_ptr,
                      struct nexus_mac         * mac);

/**
 * Decrypts the data buffer in external memory
 * @param data_buffer
 * @param crypto_ctx
 * @param mac
 */
int
nexus_data_buffer_get(struct nexus_data_buffer * data_buffer,
                      struct nexus_crypto_ctx  * crypto_ctx,
                      struct nexus_mac         * mac);

/**
 * Frees the nexus_data_buffer
 * @param data_buffer
 */
void
nexus_data_buffer_free(struct nexus_data_buffer * data_buffer);
