#pragma once

#include <nexus_fs.h>

/**
 * Manages all the I/O operations on disk. Called from ocalls and during file crypto
 *
 * @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
 */

struct sgx_backend;


typedef enum {
    FILE_ENCRYPT = 1,
    FILE_DECRYPT = 2
} file_crypto_mode;


struct nexus_file_crypto {
    file_crypto_mode     mode;

    size_t               trusted_xfer_id;

    size_t               offset; // current_offset

    char               * filepath;

    struct sgx_backend * sgx_backend;
};


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
              size_t                size,
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
io_buffer_hardlink(struct nexus_uuid   * link_uuid,
                   struct nexus_uuid   * target_uuid,
                   struct nexus_volume * volume);

int
io_buffer_rename(struct nexus_uuid   * from_uuid,
                 struct nexus_uuid   * to_uuid,
                 struct nexus_volume * volume);


int
io_manager_flush_dirty(struct sgx_backend * sgx_backend);




struct nexus_file_crypto *
io_file_crypto_start(int                  trusted_xfer_id,
                     file_crypto_mode     mode,
                     char               * filepath,
                     struct sgx_backend * sgx_backend);

int
io_file_crypto_seek(struct nexus_file_crypto * file_crypto, size_t offset);

int
io_file_crypto_update(struct nexus_file_crypto * file_crypto,
                      const uint8_t            * input,
                      uint8_t                  * output,
                      size_t                     nbytes);

int
io_file_crypto_finish(struct nexus_file_crypto * file_crypto);
