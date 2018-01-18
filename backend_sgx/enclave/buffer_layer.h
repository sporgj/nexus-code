#pragma once

/**
 * Allocates a new buffer of the given size
 * @param total_size
 * @param p_untrusted_ptr
 * @return the untrusted address
 */
struct nexus_uuid *
buffer_layer_alloc(size_t total_size, uint8_t ** p_untrusted_ptr);


/**
 * Create a `nexus_buffer` with an existing malloced untrusted pointer
 * @param untrusted_addr
 * @param size
 * @return the uuid pointint to the nexus_buffer
 */
struct nexus_uuid *
buffer_layer_create(uint8_t * untrusted_addr, size_t size);

/**
 * Deallocates an allocated buffer
 * @param buffer_uuid
 */
int
buffer_layer_free(struct nexus_uuid * buffer_uuid);
