#pragma once

/**
 * Starts a new file operation.
 * @param op is the operation to use (WRITEOP?READOP) TODO change to enum
 * @param fpath is the file path
 * @param max_xfer_size is the maximum amount of data to be sent at anytime
 * @param filelength is the file length
 * @param retptr will contain the return val
 * @return NULL if operation fails
 */
xfer_context_t *
fileops_start(int op,
              const char * fpath,
              uint32_t max_chunk_size,
              uint32_t filelength,
              int * retptr);

/**
 * Gets the transfer context
 * @param id is its id
 * @reutrn NULL if id is invalid
 */
xfer_context_t *
fileops_get_context(size_t id);

/**
 * Processes the transfer
 * @param ctx is the context to process
 * @return 0 on success
 */
int
fileops_process_data(xfer_context_t * ctx);

/**
 * Closes the file operation
 * @param id is the id of the file operation
 * @return 0 on success
 */
int
fileops_finish(size_t id);
