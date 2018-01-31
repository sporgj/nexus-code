#pragma once

#include <stdint.h>


// represents a generic buffer of memory
struct nexus_sealed_buf;

/**
 * Creates sealed_buffer from preallocated buffer
 * @param uuid
 * @return a sealed_buffer
 */
struct nexus_sealed_buf *
nexus_sealed_buf_create(struct nexus_uuid * uuid);

/**
 * Allocates new sealed_buf of specified size
 * @param size
 * @return sealed_buffer
 */
struct nexus_sealed_buf *
nexus_sealed_buf_new(size_t size);

/**
 * Frees sealed_buf with its allocated resources
 * @param sealed_buf
 */
void
nexus_sealed_buf_free(struct nexus_sealed_buf * sealed_buf);

/**
 * Copies the buffer into enclave memory and returns the pointer
 * @param sealed_buf
 * @param buffer_size is the size of the returned buffer
 * @return the unsealed buffer contents
 */
uint8_t *
nexus_sealed_buf_get(struct nexus_sealed_buf * sealed_buf, size_t * buffer_size);

/**
 * Copies data into uninternal memory
 * @param sealed_buf
 */
int
nexus_sealed_buf_put(struct nexus_sealed_buf * sealed_buf);

/**
 * Writes the sealed buffer's buffer uuid to an external UUID pointer
 * @param sealed_buf
 * @param volkey_uuid
 * @return NULL
 */
int
nexus_sealed_buf_flush(struct nexus_sealed_buf * sealed_buf, struct nexus_uuid * bufuuid_out);
