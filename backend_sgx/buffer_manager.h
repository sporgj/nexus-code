/**
 * Manages buffer_manager allocated in untrusted memory
 */

#pragma once


struct __filenode_info {
    uint32_t    metadata_size;
    uint32_t    filesize;
} __attribute__((packed));


struct metadata_buf {
    struct nexus_uuid          uuid;

    uint8_t                  * addr;

    size_t                     size;

    size_t                     timestamp; // last time it was read on disk

    size_t                     locked_file_read_offset; // offset where metadata is stored
  
    nexus_io_flags_t           locked_file_flags;

    struct nexus_file_handle * locked_file; // when writing to a metadata object
};



struct buffer_manager;

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

