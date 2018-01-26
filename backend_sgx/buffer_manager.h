/**
 * Manages buffer_manager allocated in untrusted memory
 */

#pragma once

struct buffer_manager;

struct buffer_manager *
new_buffer_manager();

void
free_buffer_manager(struct buffer_manager * buf_manager);


/**
 * Allocates a new buffer with specified size
 * @param size
 * @param dest_uuid
 * @return address of the newly allocated buffer
 */
uint8_t *
buffer_manager_alloc(struct buffer_manager * buffer_manager,
                     size_t                  size,
                     struct nexus_uuid     * dest_uuid);

/**
 * Creates a new buffer from the address and size. The buffer keeps a reference
 * to addr.
 * @param addr is the malloced address
 * @param size
 * @return uuid
 */
struct nexus_uuid *
buffer_manager_add(struct buffer_manager * buffer_manager, uint8_t * addr, size_t size);

/**
 * Returns the address stored at uuid
 * @param uuid
 * @param p_buffer_size will contain the size of the buffer
 * @return the buffer address. NULL on failure
 */
uint8_t *
buffer_manager_get(struct buffer_manager * buffer_manager,
                   struct nexus_uuid     * uuid,
                   size_t                * p_buffer_size);

/**
 * Frees buffer with specified uuid
 * @param uuid
 */
void
buffer_manager_delete(struct buffer_manager * buffer_manager, struct nexus_uuid * uuid);
