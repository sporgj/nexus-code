#pragma oncec

#include <stdint.h>


// represents a generic buffer of memory
struct nexus_sealed_buf;

/**
 * Creates raw buffer from existing preallocated untrusted buffer
 * @param untrusted_addr
 * @param size
 */
struct nexus_sealed_buf *
nexus_sealed_buf_create(void * untrusted_addr, size_t size);

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
 */
uint8_t *
nexus_sealed_buf_get(struct nexus_sealed_buf * sealed_buf);

/**
 * Copies data into untrusted memory
 * @param sealed_buf
 * @param trusted_buffer
 */
int
nexus_sealed_buf_put(struct nexus_sealed_buf * sealed_buf, uint8_t * trusted_addr);
