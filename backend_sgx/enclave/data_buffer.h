#pragma once

#include "crypto_context.h"
#include "transfer_layer.h"

#include <nexus_mac.h>

struct data_buffer;

/**
 * Creates a new data_buffer from an external address. A data buffer can only encrypt a
 * chunk at a time.
 *
 * @param external_addr
 * @param chunk_offset
 * @return chunk_size
 */
struct nexus_data_buf *
nexus_data_buf_create(size_t chunk_size);

/**
 * Start the cryptographic process
 * @param data_buffer
 * @param crypto_context
 * @param encrypt (true to encrypt)
 */
void
nexus_data_buf_start(struct nexus_data_buf   * data_buffer,
                     struct nexus_crypto_ctx * crypto_context,
                     xfer_op_t                 mode);

/**
 * Completes the data_buffer
 * @param data_buffer
 * @param mac
 */
void
nexus_data_buf_finish(struct nexus_data_buf * data_buffer, struct nexus_mac * mac);

/**
 * Continue with the encryption/decryption
 * @param data_buffer
 * @param buflen
 * @param left_over
 */
int
nexus_data_buf_update(struct nexus_data_buf * data_buffer,
                      uint8_t               * external_addr,
                      size_t                  buflen,
                      size_t                * left_over);

/**
 * Frees the nexus_data_buf
 * @param data_buffer
 */
void
nexus_data_buf_free(struct nexus_data_buf * data_buffer);
