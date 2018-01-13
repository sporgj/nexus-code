#pragma oncec

#include "raw_buffer.h"

#include "nexus_key.h"

struct sealed_buffer {
    size_t  size;
    uint8_t untrusted_buffer[0];
};

/**
 * Allocates a sealed_buffer in untrusted memory and seals (using the enclave
 * seaing key) the data into the buffer
 *
 * @param data
 * @param size
 *
 * @return sealed_buffer 
 */
struct sealed_buffer *
sealed_buffer_put(void * data, size_t size);

/**
 * Unseals the content of the sealed buffer and returns the content
 * @param sealed_buffer
 */
void *
sealed_buffer_get(struct sealed_buffer * sealed_buffer);
