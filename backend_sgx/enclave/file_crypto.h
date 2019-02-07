#pragma once

/**
 * Handles file data transfer
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */


/**
 * Creates a new file crypto context and returns an id
 * @return -1 on FAILURE
 */
int
file_crypto_new(struct nexus_metadata * metadata, nexus_crypto_mode_t mode);

int
file_crypto_update(int       xfer_id,
                   uint8_t * input_buffer,
                   uint8_t * output_buffer,
                   size_t    size,
                   size_t  * processed_bytes);

int
file_crypto_seek(int xfer_id, size_t offset);


int
file_crypto_finish(int xfer_id);
