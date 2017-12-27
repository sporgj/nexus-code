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



int
ocall_metadata_get(struct nexus_uuid        * uuid,
                   struct nexus_uuid_path   * uuid_path_untrusted,
                   struct nexus_raw_buffer ** p_raw_buffer_untrusted,
                   void                     * backend_info)
{
    struct nexus_raw_buffer * raw_buffer = NULL;

    int ret = -1;


    raw_buffer = nexus_malloc(sizeof(struct nexus_raw_buffer));

    // call the metadata store
    {
        struct sgx_backend_info * sgx_backend = NULL;

        sgx_backend = (struct sgx_backend_info *)backend_info;

        ret = nexus_datastore_get_uuid(sgx_backend->volume->metadata_store,
                                       uuid,
                                       NULL,
                                       &raw_buffer->buffer,
                                       (uint32_t *)&raw_buffer->buflen);

        if (ret != 0) {
            log_error("nexus_datastore_get_uuid FAILED");
            goto out;
        }
    }

    *p_raw_buffer_untrusted = raw_buffer;

    ret = 0;
out:
    if (ret) {
        nexus_free(raw_buffer);
    }

    return ret;
}

int
ocall_metadata_set(struct nexus_uuid       * uuid,
                   struct nexus_uuid_path  * uuid_path_untrusted,
                   struct nexus_raw_buffer * raw_buffer_untrusted,
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


