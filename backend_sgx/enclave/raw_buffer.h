#pragma once

#include <stdint.h>

#include "sgx_backend_common.h"

/**
 * allocates a raw_buffer structure in untrusted memory and copies content
 * of trusted buffer
 * @param trusted_buffer
 * @param size
 *
 * @return new raw_buffer
 */
struct raw_buffer *
raw_buffer_put(void * trusted_buffer, size_t size);

/**
 * Initializes a raw_buffer
 * @param raw_buffer
 * @param untrusted_addr
 * @param size
 *
 * @return a new raw_buffer
 */

void
raw_buffer_init(struct raw_buffer * raw_buffer,
                void              * untrusted_addr,
                size_t              size);

/**
 * Returns the pointer to the untrusted ptr
 * @param raw_buffer
 * @return the size of the raw_buffer
 */
void *
raw_buffer_get(struct raw_buffer * raw_buffer);

/**
 * Returns the size of the raw buffer
 * @param raw_buffer
 * @return the size of the raw_buffer
 */
size_t
raw_buffer_size(struct raw_buffer * raw_buffer);

/**
 * Copies the content of the buffer into the enclave and returns buffer
 * @param raw_buffer
 * @return NULL
 */
void *
raw_buffer_read_trusted(struct raw_buffer * raw_buffer);

/**
 * Free an externally allocated raw_buffer
 * @param raw_buffer_ext
 */
void
raw_buffer_free_ext(struct raw_buffer * raw_buffer_ext);
