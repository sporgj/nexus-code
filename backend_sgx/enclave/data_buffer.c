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
nexus_data_buf_new(struct nexus_crypto_ctx * crypto_context,
                   size_t                    chunk_size,
                   nexus_crypto_mode_t       mode)
{
    struct nexus_data_buf * data_buffer = NULL;

    data_buffer = nexus_malloc(sizeof(struct nexus_data_buf));

    data_buffer->chunk_size = chunk_size;

    nexus_init_key(&data_buffer->iv, NEXUS_RAW_128_KEY);
    nexus_copy_key(&(crypto_context->iv), &data_buffer->iv);


    mbedtls_gcm_init(&data_buffer->gcm_context);

    mbedtls_gcm_setkey(&data_buffer->gcm_context,
                       MBEDTLS_CIPHER_ID_AES,
                       crypto_context->key.key,
                       nexus_key_bits(&(crypto_context->key)));

    mbedtls_gcm_starts(&data_buffer->gcm_context,
                       mode == NEXUS_ENCRYPT ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                       data_buffer->iv.key,
                       nexus_key_bytes(&data_buffer->iv),
                       NULL,
                       0);

    return data_buffer;
}

int
nexus_data_buf_write(struct nexus_data_buf * data_buffer,
                     uint8_t               * external_input_addr,
                     uint8_t               * external_output_addr,
                     size_t                  buflen)
{
    uint8_t input_buffer[CRYPTO_BUFFER_SIZE]  = { 0 }; // XXX: is zeroing really necessary?
    uint8_t output_buffer[CRYPTO_BUFFER_SIZE] = { 0 };

    uint8_t * external_input_ptr  = NULL;
    uint8_t * external_output_ptr = NULL;

    int nbytes     = 0;
    int bytes_left = 0;

    int ret = -1;


    bytes_left = buflen;

    external_input_ptr  = external_input_addr;
    external_output_ptr = external_output_addr;

    while (bytes_left > 0) {
        nbytes = min(bytes_left, sizeof(input_buffer));

        memcpy(input_buffer, external_input_ptr, nbytes);

        ret = mbedtls_gcm_update(&data_buffer->gcm_context,
                                 nbytes,
                                 input_buffer,
                                 output_buffer);

        if (ret != 0) {
            log_error("mbedtls_gcm_update FAILED\n");
            return -1;
        }

        memcpy(external_output_ptr, output_buffer, nbytes);

        external_input_ptr  += nbytes;
        external_output_ptr += nbytes;

        bytes_left          -= nbytes;
    }

    return 0;
}

void
nexus_data_buf_flush(struct nexus_data_buf * data_buffer, struct nexus_mac * mac)
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
