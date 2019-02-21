#pragma once

#include <nexus_fs.h>

#include <pthread.h>

/**
 * Manages all the I/O operations on disk. Called from ocalls and during file crypto
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

struct sgx_backend;

struct metadata_buf;


typedef enum {
    FILE_ENCRYPT = 1,
    FILE_DECRYPT = 2
} file_crypto_mode;


// structure manages the streaming interface for encrypting/decrypting file content
struct nexus_file_crypto {
    size_t                      trusted_xfer_id;

    size_t                      filesize;



    file_crypto_mode            mode;

    size_t                      offset; // current_offset

    char                      * filepath;


    struct nexus_file_handle  * file_handle;


    struct metadata_buf       * metadata_buf;

    struct sgx_backend        * sgx_backend;
};



// ------------------------
//  metadata operations
// ------------------------

uint8_t *
io_buffer_alloc(struct nexus_uuid * uuid, size_t size, struct nexus_volume * volume);

uint8_t *
io_buffer_get(struct nexus_uuid   * uuid,
              nexus_io_flags_t      flags,
              size_t              * p_size,
              size_t              * timestamp,
              struct nexus_volume * volume);
int
io_buffer_put(struct nexus_uuid   * uuid,
              uint8_t             * buffer,
              size_t                metadata_size,
              size_t                data_size,
              size_t              * timestamp,
              struct nexus_volume * volume);

struct metadata_buf *
io_buffer_lock(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_volume * volume);

struct metadata_buf *
io_buffer_unlock(struct nexus_uuid * uuid, struct nexus_volume * volume);


int
io_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume);

int
io_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume);

int
io_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume);


int
io_buffer_truncate(struct nexus_uuid * uuid, size_t filesize, struct sgx_backend * sgx_backend);


// ------------------------
//  file crypto operations
// ------------------------

struct nexus_file_crypto *
io_file_crypto_start(int                  trusted_xfer_id,
                     struct nexus_uuid  * uuid,
                     file_crypto_mode     mode,
                     size_t               filesize,
                     char               * filepath,
                     struct sgx_backend * sgx_backend);

int
io_file_crypto_seek(struct nexus_file_crypto * file_crypto, size_t offset);

int
io_file_crypto_read(struct nexus_file_crypto * file_crypto, uint8_t * output_buffer, size_t nbytes);

int
io_file_crypto_write(struct nexus_file_crypto  * file_crypto,
                     const uint8_t             * input_buffer,
                     size_t                      nbytes);

int
io_file_crypto_finish(struct nexus_file_crypto * file_crypto);

