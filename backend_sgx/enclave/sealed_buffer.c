#include <sgx_tseal.h>

#include "internal.h"


struct nexus_sealed_buf {
    struct nexus_uuid * buffer_uuid;

    size_t    untrusted_size;
    uint8_t * untrusted_addr;

    size_t    trusted_size;
    uint8_t * trusted_addr;
};


struct nexus_sealed_buf *
nexus_sealed_buf_create(void * untrusted_addr, size_t untrusted_size)
{
    struct nexus_sealed_buf * sealed_buf = NULL;

    sealed_buf = nexus_malloc(sizeof(struct nexus_sealed_buf));

    sealed_buf->buffer_uuid = buffer_layer_create(untrusted_addr, untrusted_size);
    if (sealed_buf->buffer_uuid == NULL) {
        nexus_free(sealed_buf);
        log_error("buffer_layer_create FAILED\n");
        return NULL;
    }

    sealed_buf->untrusted_addr = untrusted_addr;
    sealed_buf->untrusted_size = untrusted_size;

    return sealed_buf;
}

struct nexus_sealed_buf *
nexus_sealed_buf_new(size_t size)
{
    struct nexus_sealed_buf * sealed_buf = NULL;

    sealed_buf = nexus_malloc(sizeof(struct nexus_sealed_buf));

    sealed_buf->trusted_size = size;

    return sealed_buf;
}

void
nexus_sealed_buf_free(struct nexus_sealed_buf * sealed_buf)
{
    if (sealed_buf->buffer_uuid) {
        buffer_layer_free(sealed_buf->buffer_uuid);
    }

    nexus_free(sealed_buf);
}

uint8_t *
nexus_sealed_buf_get(struct nexus_sealed_buf * sealed_buf)
{
    sgx_sealed_data_t * sealed_data = NULL;

    uint32_t payload_size = 0;

    int ret = -1;


    if (sealed_buf->trusted_addr != NULL) {
        return sealed_buf->trusted_addr;
    }

    if (sealed_buf->untrusted_addr == NULL) {
        log_error("raw buffer untrusted_addr is NULL");
        return NULL;
    }

    // XXX copy the buffer into trusted memory
    sealed_data = nexus_malloc(sealed_buf->untrusted_size);
    memcpy(sealed_data, sealed_buf->untrusted_addr, sealed_buf->untrusted_size);


    payload_size = sgx_get_encrypt_txt_len(sealed_data);

    if (payload_size == UINT32_MAX || payload_size > sealed_buf->untrusted_size) {
        log_error("sgx_get_encrypt_txt_len FAILED\n");
        goto out;
    }


    // now allocate the buffer and unseal
    sealed_buf->trusted_size = payload_size;
    sealed_buf->trusted_addr = nexus_malloc(payload_size);

    ret = sgx_unseal_data(sealed_data, NULL, 0, sealed_buf->trusted_addr, &payload_size);
    if (ret) {
        log_error("sgx_unseal_data FAILED \n");
        goto out;
    }

    ret = 0;
out:
    if (sealed_data) {
        nexus_free(sealed_data);
    }

    if (ret) {
        nexus_free(sealed_buf->trusted_addr);
        sealed_buf->trusted_addr = NULL;
    }

    return sealed_buf->trusted_addr;
}

/**
 * Copies data into untrusted memory
 * @param trusted_buffer
 */
int
nexus_sealed_buf_put(struct nexus_sealed_buf * sealed_buf, uint8_t * trusted_addr)
{
    sgx_sealed_data_t * sealed_data = NULL;

    int ret = -1;


    sealed_buf->untrusted_size = sgx_calc_sealed_data_size(0, sealed_buf->trusted_size);

    if (sealed_buf->untrusted_addr == NULL) {
        sealed_buf->buffer_uuid = buffer_layer_alloc(sealed_buf->untrusted_size,
                                                     &sealed_buf->untrusted_addr);

        if (sealed_buf->buffer_uuid == NULL) {
            log_error("buffer_layer_alloc FAILED\n");
            return -1;
        }
    }

    // seal the data
    sealed_data = nexus_malloc(sealed_buf->untrusted_size);

    ret = sgx_seal_data(0,
                        NULL,
                        sealed_buf->trusted_size,
                        trusted_addr,
                        sealed_buf->untrusted_size,
                        sealed_data);

    if (ret) {
        log_error("sgx_seal_data() FAILED\n");
        goto out;
    }

    memcpy(sealed_buf->untrusted_addr, sealed_data, sealed_buf->untrusted_size);


    ret = 0;
out:
    if (sealed_data) {
        nexus_free(sealed_data);
    }

    return ret;
}
