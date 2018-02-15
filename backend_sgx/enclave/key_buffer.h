#pragma once

#include <nexus_key.h>

/**
 * Copies a key buffer
 * @param src_buffer
 * @param dst_buffer
 */
void
key_buffer_copy(struct nexus_key_buffer * src_buffer, struct nexus_key_buffer * dst_buffer);

/**
 * Frees a key buffer
 * @param key buffer
 */
void
key_buffer_free(struct nexus_key_buffer * key_buffer);

/**
 * Extracts the raw key from a key_buffer
 * @param key_buffer
 * @param raw_key_type: the type the returned key should be
 * @return NULL on failure
 */
struct nexus_key *
key_buffer_get(struct nexus_key_buffer * key_buffer, nexus_key_type_t raw_key_type);

/**
 * Creates a new key buffer from a nexus key
 * @param key
 * @param protected_key_type  WRAPPED/SEALED
 * @return key_buffer
 */
struct nexus_key_buffer *
key_buffer_put(struct nexus_key * key, nexus_key_type_t protected_key_type);


