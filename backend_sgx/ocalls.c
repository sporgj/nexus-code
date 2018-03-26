#include "internal.h"

// -------------------------- utilities -----------------------

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
    fflush(stdout);
}



// ------------------- Buffer Management ---------------------------

uint8_t *
ocall_buffer_alloc(size_t size, struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    return buffer_manager_alloc(sgx_backend->buf_manager, size, uuid);
}

void
ocall_buffer_put(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    buffer_manager_put(sgx_backend->buf_manager, uuid);
}

uint8_t *
ocall_buffer_get(struct nexus_uuid * metadata_uuid, size_t * p_size, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = NULL;

    struct __buf * buf = NULL;

    uint8_t * buffer_addr = NULL;

    int ret = -1;


    sgx_backend = (struct sgx_backend *)volume->private_data;

    // check the buffer manager
    {
        buf = buffer_manager_get(sgx_backend->buf_manager, metadata_uuid);

        *p_size = buf->size;

        if (buf) {
            // TODO additional freshness checks here

            return buf->addr;
        }
    }

    // let's get it from the backing metadata store

    ret = nexus_datastore_get_uuid(volume->metadata_store,
                                   metadata_uuid,
                                   NULL,
                                   &buffer_addr,
                                   (uint32_t *)p_size);

    if (ret != 0) {
        log_error("nexus_datastore_get_uuid FAILED\n");
        return NULL;
    }

    ret = buffer_manager_add(sgx_backend->buf_manager, buffer_addr, *p_size, metadata_uuid);

    if (ret != 0) {
        log_error("buffer_manager_add FAILED\n");

        nexus_free(buffer_addr);
        return NULL;
    }

    return buffer_addr;
}

int
ocall_buffer_flush(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = NULL;

    struct __buf * buf = NULL;

    int ret = -1;


    sgx_backend = (struct sgx_backend *)volume->private_data;


    buf = buffer_manager_get(sgx_backend->buf_manager, metadata_uuid);

    if (buf == NULL) {
        log_error("buffer_manager_get returned NULL\n");
        return -1;
    }


    ret = nexus_datastore_put_uuid(sgx_backend->volume->metadata_store,
                                   metadata_uuid,
                                   NULL,
                                   buf->addr,
                                   buf->size);

    buffer_manager_put(sgx_backend->buf_manager, &buf->uuid);

    if (ret) {
        log_error("nexus_datastore_put_uuid FAILED\n");
        return -1;
    }

    return 0;
}

int
ocall_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = NULL;

    sgx_backend = (struct sgx_backend *)volume->private_data;

    buffer_manager_del(sgx_backend->buf_manager, metadata_uuid);

    return nexus_datastore_del_uuid(sgx_backend->volume->metadata_store, metadata_uuid, NULL);
}

int
ocall_buffer_hardlink(struct nexus_uuid   * link_uuid,
                      struct nexus_uuid   * target_uuid,
                      struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = NULL;

    sgx_backend = (struct sgx_backend *)volume->private_data;

    return nexus_datastore_hardlink_uuid(sgx_backend->volume->metadata_store,
                                         link_uuid,
                                         NULL,
                                         target_uuid,
                                         NULL);
}
