#include "enclave_internal.h"

#include <mbedtls/gcm.h>

struct nexus_data_buf {
    size_t    chunk_size;
    size_t    completed;

    uint8_t * external_addr;

    struct nexus_key iv;

    mbedtls_gcm_context gcm_context;
};


struct nexus_data_buf *
nexus_data_buf_create(size_t chunk_size)
{
    struct nexus_data_buf * data_buffer = NULL;

    data_buffer = nexus_malloc(sizeof(struct nexus_data_buf));

    data_buffer->chunk_size    = chunk_size;

    mbedtls_gcm_init(&data_buffer->gcm_context);

    nexus_init_key(&data_buffer->iv, NEXUS_RAW_128_KEY);

    return data_buffer;
}

void
nexus_data_buf_start(struct nexus_data_buf    * data_buffer,
                     struct nexus_crypto_ctx  * crypto_context,
                     xfer_op_t                  mode)
{
    nexus_copy_key(&(crypto_context->iv), &data_buffer->iv);

    mbedtls_gcm_setkey(&data_buffer->gcm_context,
                       MBEDTLS_CIPHER_ID_AES,
                       crypto_context->key.key,
                       nexus_key_bits(&(crypto_context->key)));

    mbedtls_gcm_starts(&data_buffer->gcm_context,
                       mode == XFER_ENCRYPT ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                       data_buffer->iv.key,
                       nexus_key_bytes(&data_buffer->iv),
                       NULL,
                       0);
}

int
nexus_data_buf_update(struct nexus_data_buf * data_buffer,
                      uint8_t               * external_addr,
                      size_t                  buflen,
                      size_t                * processed_bytes)
{
    uint8_t input_buffer[CRYPTO_BUFFER_SIZE]  = { 0 }; // XXX: is zeroing really necessary?
    uint8_t output_buffer[CRYPTO_BUFFER_SIZE] = { 0 };

    uint8_t * external_ptr = NULL;

    int processed  = 0;
    int nbytes     = 0;
    int bytes_left = 0;

    int ret = -1;

    /* we can only process up to one chunk at a time */
    bytes_left = data_buffer->chunk_size - data_buffer->completed;

    *processed_bytes = 0;

    if (bytes_left <= 0) {
        return 0;
    }


    bytes_left = min(bytes_left, buflen);

    external_ptr = external_addr;

    while (bytes_left > 0) {
        nbytes = min(bytes_left, sizeof(input_buffer));

        memcpy(input_buffer, external_ptr, nbytes);

        ret = mbedtls_gcm_update(&data_buffer->gcm_context,
                                 nbytes,
                                 input_buffer,
                                 output_buffer);

        if (ret != 0) {
            log_error("mbedtls_gcm_update FAILED\n");
            return -1;
        }

        memcpy(external_ptr, output_buffer, nbytes);

        external_ptr += nbytes;
        processed    += nbytes;
        bytes_left   -= nbytes;
    }

    *processed_bytes = processed;

    data_buffer->completed += processed;

    return 0;
}

void
nexus_data_buf_finish(struct nexus_data_buf * data_buffer, struct nexus_mac * mac)
{
    mbedtls_gcm_finish(&data_buffer->gcm_context, (uint8_t *)mac, sizeof(struct nexus_mac));
}

void
nexus_data_buf_free(struct nexus_data_buf * data_buffer)
{
    if (data_buffer->iv.key) {
        nexus_free_key(&data_buffer->iv);
    }

    mbedtls_gcm_free(&data_buffer->gcm_context);

    nexus_free(data_buffer);
}
