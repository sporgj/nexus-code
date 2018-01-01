#include "internal.h"

void *
ocall_calloc(size_t size)
{
    void * ptr = calloc(1, size);
    if (ptr == NULL) {
        log_error("allocation error");
    }

    return ptr;
}

void
ocall_free(void * ptr)
{
    free(ptr);
}

void
ocall_print(char * str)
{
    printf("%s", str);
}

struct crypto_buffer *
ocall_metadata_get(struct nexus_uuid      * uuid,
                   struct nexus_uuid_path * uuid_path_untrusted,
                   void                   * backend_info)
{
    struct crypto_buffer * crypto_buffer = NULL;

    int ret = -1;


    crypto_buffer = nexus_malloc(sizeof(struct crypto_buffer));

    // call the metadata store
    {
        struct sgx_backend_info * sgx_backend = NULL;

        sgx_backend = (struct sgx_backend_info *)backend_info;

        ret = nexus_datastore_get_uuid(sgx_backend->volume->metadata_store,
                                       uuid,
                                       NULL,
                                       &crypto_buffer->untrusted_addr,
                                       (uint32_t *)&crypto_buffer->size);

        if (ret != 0) {
            log_error("nexus_datastore_get_uuid FAILED");
            goto out;
        }
    }

    ret = 0;
out:
    if (ret) {
        nexus_free(crypto_buffer);

        return NULL;
    }

    return crypto_buffer;
}

int
ocall_metadata_set(struct nexus_uuid       * uuid,
                   struct nexus_uuid_path  * uuid_path_untrusted,
                   struct crypto_buffer    * crypto_buffer,
                   void                    * backend_info)
{
    return -1;
}

int
ocall_metadata_delete(struct nexus_uuid      * uuid,
                      struct nexus_uuid_path * uuid_path_untrusted,
                      void                   * backend_info)
{
    return -1;
}

int
ocall_metadata_stat(struct nexus_uuid        * uuid,
                    struct nexus_uuid_path   * uuid_path_untrusted,
                    struct nexus_stat_buffer * stat_buffer_untrusted,
                      void                   * backend_info)
{
    return -1;
}


