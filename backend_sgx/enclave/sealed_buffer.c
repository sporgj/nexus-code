#include <sgx_tseal.h>

#include "internal.h"


struct sealed_buffer *
sealed_buffer_write(void * data, size_t size)
{
    struct sealed_buffer * sealed_buffer = NULL;

    sgx_sealed_data_t * sealed_data_ptr  = NULL;
    size_t              sealed_data_size = 0;

    int ret = -1;


    // calculate how much memory we need to allocate
    // aad_len, encrypted_data_len
    sealed_data_size = sgx_calc_sealed_data_size(0, size);

    sealed_data_ptr = nexus_malloc(sealed_data_size);

    ret = sgx_seal_data(0, NULL, size, data, sealed_data_size, sealed_data_ptr);
    if (ret) {
        ocall_debug("sgx_seal_data() FAILED");
        goto out;
    }

    ret = ocall_calloc((void **)&sealed_buffer,
                       sealed_data_size + sizeof(struct sealed_buffer));

    if (ret || !sealed_buffer) {
        goto out;
    }

    sealed_buffer->size = sealed_data_size;
    memcpy(sealed_buffer->untrusted_buffer, sealed_data_ptr, sealed_data_size);

    ret = 0;
out:
    nexus_free(sealed_data_ptr);

    if (ret) {
        if (sealed_buffer) {
            ocall_free(sealed_buffer);
        }

        return NULL;
    }

    return sealed_buffer;
}

/**
 * Unseals the content of the sealed buffer and returns the content
 */
void *
sealed_buffer_read(struct sealed_buffer * sealed_buffer)
{
    sgx_sealed_data_t * sealed_data_trusted  = NULL;

    void *   unsealed_contents = NULL;
    uint32_t unsealed_size     = 0;

    int ret = -1;


    sealed_data_trusted = nexus_malloc(sealed_buffer->size);
    memcpy(sealed_data_trusted,
           sealed_buffer->untrusted_buffer,
           sealed_buffer->size);


    // allocate buffer and unseal the contents 
    {
        unsealed_contents
            = nexus_malloc(sgx_get_encrypt_txt_len(sealed_data_trusted));

        ret = sgx_unseal_data(
            sealed_data_trusted, NULL, 0, unsealed_contents, &unsealed_size);

        if (ret) {
            ocall_debug("sgx_unseal_data FAILED");
            goto out;
        }
    }

    ret = 0;
out:
    nexus_free(sealed_data_trusted);

    if (ret) {
        if (unsealed_contents) {
            nexus_free(unsealed_contents);
        }

        return NULL;
    }

    return unsealed_contents;
}
