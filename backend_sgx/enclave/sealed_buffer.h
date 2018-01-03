#pragma oncec

#include "raw_buffer.h"

#include "nexus_key.h"

/**
 * Allocates a sealed_buffer in untrusted memory and seals the data into
 * the buffer
 *
 * @param data
 * @param size
 */
struct sealed_buffer *
sealed_buffer_write(void * data, size_t size);

/**
 * Unseals the content of the sealed buffer and returns the content
 * @param sealed_buffer
 */
void *
sealed_buffer_read(struct sealed_buffer * sealed_buffer);
