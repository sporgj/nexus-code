#pragma once

#include <stdint.h>

#include <nexus_uuid.h>

#include "crypto.h"

// represents an encrypted metadata object

struct crypto_buffer;


// contains the raw buffer written to disk
struct metadata_header {

    // used to encrypt the metadata content
    struct crypto_context crypto_context;

    struct metadata_info {
        uint32_t version;

        uint32_t buffer_size;

        struct nexus_uuid my_uuid;
    } info;

} __attribute__((packed));



struct crypto_buffer *
crypto_buffer_alloc(void * untrusted_addr, size_t size);

struct crypto_buffer *
crypto_buffer_new(size_t size);

void
crypto_buffer_free(struct crypto_buffer * crypto_buffer);

/**
 * Decrypts and returns the crypto buffer plaintext
 * @param crypto_buffer
 * @return NULL on failure
 */
void *
crypto_buffer_read(struct crypto_buffer * crypto_buffer, crypto_mac_t * mac);

/**
 * Writes plaintext metadata content into the crypto buffer
 *
 * @param crypto_buffer
 * @param uuid
 * @param serialized_buffer
 * @param serialized_buflen
 * @param mac
 *
 * @return 0 on success
 */
int
crypto_buffer_write(struct crypto_buffer * crypto_buffer,
                    struct nexus_uuid    * uuid,
                    uint8_t              * serialized_buffer,
                    size_t                 serialized_buflen,
                    crypto_mac_t         * mac);
