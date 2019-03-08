/**
 * Manages buffer_manager allocated in untrusted memory
 */
#pragma once

#include <stdint.h>
#include <sys/time.h>

#include <nexus_fs.h>


struct metadata_buf {
    struct nexus_uuid             uuid;

    uint8_t                     * buffer_addr;
    size_t                        buffer_size;
    time_t                        buffer_time; // last time buffer was updated

    pthread_mutex_t               file_mutex;

    nexus_io_flags_t              io_flags;

    time_t                        sync_time;
    time_t                        flush_time; // last time we flush to disk

    struct nexus_file_handle    * file_handle;  // file handle to the datastore
    struct nexus_file_handle    * batch_handle;

    bool                          sync_file_exists;

    bool                          batch_file_exists;

    bool                          batch_mode_created;  // if created in batch mode
    bool                          batch_mode_modified;  // if modified in batch mode

    size_t                        data_size;

    bool                          is_dirty;     // if it is unflushed
    bool                          is_syncing;

    struct sgx_backend          * backend;
};


struct buffer_manager {
    struct nexus_hashtable      * buffers_table;

    size_t                        table_size;
};

struct buffer_manager *
buffer_manager_init();

void
buffer_manager_destroy(struct buffer_manager * buf_manager);


/**
 * Creates a new buffer from the address and size. The buffer keeps a reference
 * to addr. The new buffer gets timestamped with the current time.
 *
 * @param addr is the malloced address
 * @param size
 * @param uuid
 * @return 0 on success
 */

void
buffer_manager_add(struct buffer_manager * buf_manager, struct metadata_buf * buf);


struct metadata_buf *
buffer_manager_find(struct buffer_manager * buffer_manager, struct nexus_uuid * uuid);

/**
 * Deletes a file from the buffer manager
 * @param buffer_manager
 * @param uuid
 */
void
buffer_manager_del(struct buffer_manager * buffer_manager, struct nexus_uuid * uuid);

void
__free_metadata_buf(struct metadata_buf * buf);
