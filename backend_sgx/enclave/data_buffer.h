#pragma once

#include "crypto_context.h"

#include <nexus_mac.h>

struct nexus_data_buf;

/**
 * Start the cryptographic process
 * @param data_buffer
 * @param crypto_context
 * @param chunk_size
 * @param mode
 */
struct nexus_data_buf *
nexus_data_buf_new(struct nexus_crypto_ctx * crypto_context,
                   size_t                    chunk_size,
                   nexus_crypto_mode_t       mode);

/**
 * Continue with the encryption/decryption
 * @param data_buffer
 * @param external_input_addr
 * @param external_output_addr
 * @param buflen
 */
int
nexus_data_buf_write(struct nexus_data_buf * data_buffer,
                     uint8_t               * external_input_addr,
                     uint8_t               * external_output_addr,
                     size_t                  buflen);

/**
 * Writes the result of the encryption to the mac
 * @param data_buffer
 * @param mac
 */
void
nexus_data_buf_flush(struct nexus_data_buf * data_buffer, struct nexus_mac * mac);

/**
 * frees the data buffer
 */
void
nexus_data_buf_free(struct nexus_data_buf * data_buffer);
