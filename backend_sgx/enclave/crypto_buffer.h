#pragma once

#include <stdint.h>

#include "sgx_backend_common.h"

#include "nexus_mac.h"


#define CRYPTOBUF_INVALID_VERSION (UINT32_MAX)


// represents an encrypted metadata object
struct nexus_crypto_buf;

/**
 * allocates a new crypto buffer with specified untrusted address and size
 * @param untrusted_addr
 * @param untrusted_size
 *
 * @return nexus_crypto_buf
 */
struct nexus_crypto_buf *
nexus_crypto_buf_create(struct nexus_uuid * uuid, nexus_io_flags_t flags);

/**
 * Creates a new crypto buffer which will encrypt a metadata buffer of size.
 *
 * @param size
 * @param version
 * @param uuid
 * @return crypto_buf
 */
struct nexus_crypto_buf *
nexus_crypto_buf_new(size_t size, uint32_t version, struct nexus_uuid * uuid);

void
nexus_crypto_buf_free(struct nexus_crypto_buf * buf);

/**
 * Returns the version of the crypto buffer
 * @param buf
 * @return CRYPTOBUF_INVALID_VERSION on failure
 */
uint32_t
nexus_crypto_buf_version(struct nexus_crypto_buf * buf);

/**
 * Allows you to compute the sha256 of the external buffer
 * @param crypto_buf
 * @param sha_context
 *
 * return -1 on FAILURE
 */
int
nexus_crypto_buf_sha256_exterior(struct nexus_crypto_buf * crypto_buf,
                                 mbedtls_sha256_context  * sha_context);

/**
 * Returns a pointer to trusted memory containing the buffer's data
 *    Will decrypt existing data if it exists.
 * @param nexus_crypto_buf
 * @return NULL on failure
 */
void *
nexus_crypto_buf_get(struct nexus_crypto_buf * buf, size_t * buffer_size, struct nexus_mac * mac);

int
nexus_crypto_buf_put(struct nexus_crypto_buf * buf, struct nexus_mac * mac);

void
nexus_crypto_buf_set_datasize(struct nexus_crypto_buf * buf, size_t data_size);
