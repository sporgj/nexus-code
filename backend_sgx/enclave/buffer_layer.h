#pragma once
#include "nexus_uuid.h"

/**
 * Allocates a new buffer of the given size and acquires a reference to the buffek
 * @param total_size
 * @param uuid
 * @return the address to the buffer
 */
void *
buffer_layer_alloc(size_t total_size, struct nexus_uuid * uuid);


/**
 * Acquires a reference to an externally allocated buffer
 * @param uuid
 * @param size
 * @return the address to the external buffer.
 */
void *
buffer_layer_get(struct nexus_uuid * uuid, size_t * size);

/**
 * Drops reference to a specified buffer
 * @param buffer_uuid
 * @return 0 on success
 */
int
buffer_layer_put(struct nexus_uuid * buffer_uuid);
