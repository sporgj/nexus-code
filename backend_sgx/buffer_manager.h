/**
 * Manages buffer_manager allocated in untrusted memory
 */

#pragma once

struct __buf {
    struct nexus_uuid   uuid;

    int                 refcount; // TODO consider switching to atomic.h

    uint8_t           * addr;

    size_t              size;

    bool                on_disk;
};

struct buffer_manager;

struct buffer_manager *
buffer_manager_init();

void
buffer_manager_destroy(struct buffer_manager * buf_manager);


/**
 * Allocates a new buffer with specified size
 * @param size
 * @param dest_uuid
 * @return address of the newly allocated buffer
 */
uint8_t *
buffer_manager_alloc(struct buffer_manager * buf_manager, size_t size, struct nexus_uuid * buf_uuid);

/**
 * Creates a new buffer from the address and size. The buffer keeps a reference
 * to addr.
 * @param addr is the malloced address
 * @param size
 * @param uuid
 * @return 0 on success
 */
int
buffer_manager_add(struct buffer_manager * buf_manager, uint8_t * addr, size_t size, struct nexus_uuid * uuid);

/**
 * Returns the address stored at uuid
 * @param uuid
 * @param p_buffer_size will contain the size of the buffer
 * @return the buffer address. NULL on failure
 */
struct __buf *
buffer_manager_get(struct buffer_manager * buffer_manager, struct nexus_uuid * uuid);

/**
 * Frees buffer with specified uuid
 * @param uuid
 */
void
buffer_manager_put(struct buffer_manager * buffer_manager, struct nexus_uuid * uuid);

/**
 * Deletes a file from the buffer manager
 * @param buffer_manager
 * @param uuid
 */
void
buffer_manager_del(struct buffer_manager * buffer_manager, struct nexus_uuid * uuid);

