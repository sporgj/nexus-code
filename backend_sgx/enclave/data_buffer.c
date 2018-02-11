#include "enclave_internal.h"

struct nexus_data_buffer {
    size_t    external_size;

    size_t    curr_offset;

    size_t    chunk_size;

    uint8_t * external_addr;

    mbedtls_aes_context aes_context;
};

/*
struct nexus_data_buffer *
nexus_data_buffer_create(uint8_t * external_addr, size_t external_size)
{
    struct nexus_data_buffer * data_buffer = NULL;

    data_buffer = nexus_malloc(sizeof(struct nexus_data_buffer));

    data_buffer->external_addr = external_addr;
    data_buffer->external_size = external_size;

    return data_buffer;
}
*/

struct nexus_data_buffer *
nexus_data_buffer_create(uint8_t * external_addr, size_t chunk_offset, size_t chunk_size)
{
    struct nexus_data_buffer * data_buffer = NULL;

    data_buffer = nexus_malloc(sizeof(struct nexus_data_buffer));

    data_buffer->curr_offset   = curr_offset;
    data_buffer->chunk_size    = chunk_size;
    data_buffer->external_addr = external_addr;

    mbedtls_aes_init(&data_buffer->aes_context);

    return data_buffer;
}

int
nexus_data_buffer_update(struct nexus_data_buffer * data_buffer,
                         size_t                     buflen,
                         size_t                   * left_over)
{

}

int
nexus_data_buffer_put(struct nexus_data_buffer * data_buffer,
                      struct nexus_crypto_ctx  * crypto_ctx_dest_ptr,
                      struct nexus_mac         * mac)
{
    struct nexus_crypto_ctx crypto_ctx;

    int ret = -1;


    nexus_crypto_ctx_generate(&crypto_ctx);

    ret = crypto_gcm_encrypt(&crypto_ctx,
                             data_buffer->external_size,
                             data_buffer->external_addr,
                             data_buffer->external_addr,
                             mac,
                             NULL, // XXX: maybe request AAD from caller ?
                             0);

    if (ret != 0) {
        log_error("crypto_gcm_encrypt() FAILED \n");
        return -1;
    }

    nexus_crypto_ctx_copy(&crypto_ctx, crypto_ctx_dest_ptr);

    return 0;
}

int
nexus_data_buffer_get(struct nexus_data_buffer * data_buffer,
                      struct nexus_crypto_ctx  * crypto_ctx,
                      struct nexus_mac         * mac)
{
    int ret = -1;


    ret = crypto_gcm_encrypt(crypto_ctx,
                             data_buffer->external_size,
                             data_buffer->external_addr,
                             data_buffer->external_addr,
                             mac,
                             NULL, // XXX: maybe request AAD from called ?
                             0);

    if (ret != 0) {
        log_error("crypto_gcm_encrypt() FAILED \n");
        return -1;
    }

    return 0;
}

void
nexus_data_buffer_free(struct nexus_data_buffer * data_buffer)
{
    nexus_free(data_buffer);
}
