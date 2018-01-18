#pragma once

#include <stdint.h>

// represents a generic buffer of memory
struct nexus_raw_buf;

/**
 * Creates raw buffer from existing preallocated untrusted buffer
 * @param untrusted_addr
 * @param size
 */
struct nexus_raw_buf *
nexus_raw_buf_create(void * untrusted_addr, size_t size);

/**
 * Allocates new raw_buf of specified size
 * @param size
 * @return raw_buffer
 */
struct nexus_raw_buf *
nexus_raw_buf_new(size_t size);

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
nexus_raw_buf_get(struct nexus_raw_buf * raw_buf);

/**
 * Copies data into untrusted memory
 * @param trusted_buffer
 */
int
nexus_raw_buf_put(struct nexus_raw_buf * raw_buf, uint8_t * trusted_addr);
