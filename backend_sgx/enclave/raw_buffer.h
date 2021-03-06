#pragma once

#include <stdint.h>

// represents a generic buffer of memory
struct nexus_raw_buf;

/**
 * Creates raw_buffer from preallocated buffer
 * @param uuid
 * @return a sealed_buffer
 */
struct nexus_raw_buf *
nexus_raw_buf_create(uint8_t * external_addr, size_t external_size);

/**
 * Frees raw_buf with its allocated resources
 * @param raw_buf
 */
void
nexus_raw_buf_free(struct nexus_raw_buf * raw_buf);

/**
 * Copies the buffer into enclave memory and returns the pointer
 */
uint8_t *
nexus_raw_buf_get(struct nexus_raw_buf * raw_buf, size_t * buffer_size);
