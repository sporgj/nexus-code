#pragma once
#include "uc_types.h"

int
fetchstore_start(int op,
                 char * fpath,
                 uint32_t max_xfer_size,
                 uint32_t file_offset,
                 uint32_t file_size,
                 int * xfer_id,
                 uint32_t * fbox_len,
                 uint32_t * total_len);

/**
 * Returns the buffer for the file operation
 * @param id is its id
 * @param valid_buflen is the valid buflen
 * @reutrn NULL if id is invalid or valid_buflen > buffer_size
 */
uint8_t **
fetchstore_get_buffer(int id, size_t valid_buflen);

/**
 * Processes the transfer
 * @param buffer is the pointer acquired from get_buffer
 * @return 0 on success
 */
int
fetchstore_process_data(uint8_t ** buffer);

/**
 * Closes the file operation
 * @param id is the id of the file operation
 * @return 0 on success
 */
int
fetchstore_finish(int id);
