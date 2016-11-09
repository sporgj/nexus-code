#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Starts a new file operation.
 * @param op is the operation to use (WRITEOP?READOP) TODO change to enum
 * @param fpath is the file path
 * @param max_xfer_size is the maximum amount of data to be sent at anytime
 * @param position is the position in the file which we are to encrypt
 * @param total_len is the file length
 * @param id will contain the id of the fileop
 * @return NULL if operation fails
 */
int
fileops_start(int op,
              const char * fpath,
              uint32_t max_chunk_size,
              int32_t position,
              uint32_t total_len,
              int * id);

/**
 * Returns the buffer for the file operation
 * @param id is its id
 * @param valid_buflen is the valid buflen
 * @reutrn NULL if id is invalid or valid_buflen > buffer_size
 */
uint8_t **
fileops_get_buffer(int id, size_t valid_buflen);

/**
 * Processes the transfer
 * @param buffer is the pointer acquired from get_buffer
 * @return 0 on success
 */
int
fileops_process_data(uint8_t ** buffer);

/**
 * Closes the file operation
 * @param id is the id of the file operation
 * @param code is the return from the finish operation
 * @return 0 on success
 */
int
fileops_finish(int id, int * code);

#ifdef __cplusplus
}
#endif
