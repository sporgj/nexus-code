#pragma once

/**
 * Allocates a new buffer of the given size
 * @param total_size
 * @param p_untrusted_ptr
 * @return the untrusted address
 */
void *
buffer_layer_alloc(size_t total_size, struct nexus_uuid * uuid);


/**
 * Create a `nexus_buffer` with an existing malloced untrusted pointer
 * @param untrusted_addr
 * @param size
 * @return the uuid pointint to the nexus_buffer
 */
void *
buffer_layer_get(struct nexus_uuid * uuid, size_t * size);

/**
 * Deallocates an allocated buffer
 * @param buffer_uuid
 */
int
buffer_layer_put(struct nexus_uuid * buffer_uuid);
