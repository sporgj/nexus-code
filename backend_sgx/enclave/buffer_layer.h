#pragma once
#include <nexus_uuid.h>

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
 * @param uuid
 * @return 0 on success
 */
int
buffer_layer_put(struct nexus_uuid * uuid);

/**
 * Locks the metadata file on disk
 */
int
buffer_layer_lock(struct nexus_uuid * uuid);

/**
 * Unlocks the previously locked file
 */
int
buffer_layer_unlock(struct nexus_uuid * uuid);

/**
 * Flushes the buffer layer to the metadata
 * @param uuid
 * @return 0 on success
 */
int
buffer_layer_flush(struct nexus_uuid * uuid);

/**
 * Creates an empty file on the datastore
 * @param uuid
 */
int
buffer_layer_new(struct nexus_uuid * uuid);

/**
 * Deletes a metadata buffer
 * @param uuid
 */
void
buffer_layer_delete(struct nexus_uuid * uuid);

/**
 * Hardlinks two metadata uuid
 * @param link_uuid
 * @param target_uuid
 * @return 0 on success
 */
int
buffer_layer_hardlink(struct nexus_uuid * link_uuid, struct nexus_uuid * target_uuid);

/**
 * Renames a metadata object on disk
 * @param from_uuid
 * @param to_uuid
 */
int
buffer_layer_rename(struct nexus_uuid * from_uuid, struct nexus_uuid * to_uuid);
