#include <sgx_tseal.h>

#include "enclave_internal.h"


struct nexus_sealed_buf {
    struct nexus_uuid uuid;

    size_t    external_size;
    uint8_t * external_addr;

    size_t    internal_size;
    uint8_t * internal_addr;
};


struct nexus_sealed_buf *
nexus_sealed_buf_create(struct nexus_uuid * uuid)
{
    struct nexus_sealed_buf * sealed_buf = NULL;

    void * external_addr = NULL;
    size_t external_size = 0;

    external_addr = buffer_layer_get(uuid, &external_size);
    if (external_addr == NULL) {
        log_error("could not retrieve external address\n");
        return NULL;
    }

    sealed_buf = nexus_malloc(sizeof(struct nexus_sealed_buf));

    sealed_buf->external_addr = external_addr;
    sealed_buf->external_size = external_size;

    nexus_uuid_copy(uuid, &sealed_buf->uuid);

    return sealed_buf;
}

struct nexus_sealed_buf *
nexus_sealed_buf_new(size_t size)
{
    struct nexus_sealed_buf * sealed_buf = NULL;

    sealed_buf = nexus_malloc(sizeof(struct nexus_sealed_buf));

    sealed_buf->internal_size = size;
    sealed_buf->internal_addr = nexus_malloc(size);

    return sealed_buf;
}

void
nexus_sealed_buf_free(struct nexus_sealed_buf * sealed_buf)
{
    if (sealed_buf->external_addr) {
        buffer_layer_put(&sealed_buf->uuid);
    }

    if (sealed_buf->internal_addr) {
        nexus_free(sealed_buf->internal_addr);
    }

    nexus_free(sealed_buf);
}

uint8_t *
nexus_sealed_buf_get(struct nexus_sealed_buf * sealed_buf, size_t * buffer_size)
{
    sgx_sealed_data_t * sealed_data = NULL;

    uint32_t payload_size = 0;

    int ret = -1;


    if (sealed_buf->internal_addr != NULL) {
        *buffer_size = sealed_buf->internal_size;

        return sealed_buf->internal_addr;
    }

    if (sealed_buf->external_addr == NULL) {
        log_error("raw buffer external_addr is NULL");
        return NULL;
    }

    sealed_data = nexus_malloc(sealed_buf->external_size);

    memcpy(sealed_data, sealed_buf->external_addr, sealed_buf->external_size);


    payload_size = sgx_get_encrypt_txt_len(sealed_data);

    if (payload_size == UINT32_MAX || payload_size > sealed_buf->external_size) {
        log_error("sgx_get_encrypt_txt_len FAILED\n");
        goto out;
    }


    // now allocate the buffer and unseal
    sealed_buf->internal_size = payload_size;
    sealed_buf->internal_addr = nexus_malloc(payload_size);

    ret = sgx_unseal_data(sealed_data, NULL, 0, sealed_buf->internal_addr, &payload_size);
    if (ret) {
        log_error("sgx_unseal_data FAILED \n");
        goto out;
    }

    *buffer_size = sealed_buf->internal_size;

    ret = 0;
out:
    if (sealed_data) {
        nexus_free(sealed_data);
    }

    if (ret) {
        nexus_free(sealed_buf->internal_addr);
        sealed_buf->internal_addr = NULL;
    }

    return sealed_buf->internal_addr;
}

/**
 * Copies data into external memory
 * @param internal_buffer
 */
int
nexus_sealed_buf_put(struct nexus_sealed_buf * sealed_buf)
{
    sgx_sealed_data_t * sealed_data = NULL;

    int ret = -1;


    sealed_buf->external_size = sgx_calc_sealed_data_size(0, sealed_buf->internal_size);

    if (sealed_buf->external_addr == NULL) {
        sealed_buf->external_addr = buffer_layer_alloc(sealed_buf->external_size,
                                                       &sealed_buf->uuid);

        if (sealed_buf->external_addr == NULL) {
            log_error("buffer_layer_alloc FAILED\n");
            return -1;
        }
    }

    // seal the data
    sealed_data = nexus_malloc(sealed_buf->external_size);

    ret = sgx_seal_data(0,
                        NULL,
                        sealed_buf->internal_size,
                        sealed_buf->internal_addr,
                        sealed_buf->external_size,
                        sealed_data);

    if (ret) {
        log_error("sgx_seal_data() FAILED\n");
        goto out;
    }

    memcpy(sealed_buf->external_addr, sealed_data, sealed_buf->external_size);


    ret = 0;
out:
    if (sealed_data) {
        nexus_free(sealed_data);
    }

    return ret;
}

int
nexus_sealed_buf_flush(struct nexus_sealed_buf * sealed_buf, struct nexus_uuid * bufuuid_out)
{
    buffer_layer_copy(&sealed_buf->uuid, bufuuid_out);

    return 0;
}
