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
 * Extracts the raw key from a wrapped key_buffer
 * @param key_buffer
 * @return NULL on failure
 */
struct nexus_key *
key_buffer_extract128(struct nexus_key_buffer * key_buffer);

/**
 * Creates a new key buffer from a nexus key
 * @param key
 * @param protected_key_type  WRAPPED/SEALED
 * @return key_buffer
 */
struct nexus_key_buffer *
key_buffer_wrap128(struct nexus_key * key);

struct nexus_key_buffer *
key_buffer_seal(struct nexus_key * key);

