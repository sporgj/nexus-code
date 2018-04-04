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

int
ocall_buffer_lock(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    struct nexus_raw_file * raw_file = NULL;

    // this blocks
    raw_file = nexus_datastore_write_start(volume->metadata_store, uuid, NULL);

    if (raw_file == NULL) {
        log_error("nexus_datastore_write_start() FAILED\n");
        return -1;
    }

    if (lock_manager_add(sgx_backend->lock_manager, uuid, raw_file)) {
        log_error("could not lock file\n");
        return -1;
    }

    return 0;
}

int
ocall_buffer_unlock(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    struct nexus_raw_file * raw_file = NULL;


    raw_file = lock_manager_drop(sgx_backend->lock_manager, uuid);

    if (raw_file == NULL) {
        log_error("could not find file in lock manager\n");
        return -1;
    }

    nexus_datastore_write_finish(volume->metadata_store, raw_file);

    return 0;
}

int
ocall_buffer_flush(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

    struct nexus_raw_file * raw_file = NULL;

    raw_file = lock_manager_get(sgx_backend->lock_manager, uuid);

    if (raw_file == NULL) {
        log_error("could not find file in lock manager\n");
        return -1;
    }


    {
        struct __buf * buf = NULL;

        int ret = -1;


        buf = buffer_manager_get(sgx_backend->buf_manager, uuid);

        if (buf == NULL) {
            log_error("buffer_manager_get returned NULL\n");
            return -1;
        }

        ret = nexus_datastore_write_bytes(volume->metadata_store, raw_file, buf->addr, buf->size);

        buffer_manager_put(sgx_backend->buf_manager, &buf->uuid);

        if (ret) {
            log_error("nexus_datastore_put_uuid FAILED\n");
            return -1;
        }

        return 0;
    }

    return 0;
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

        if (buf) {
            // TODO additional freshness checks here

            *p_size = buf->size;

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
ocall_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = NULL;

    sgx_backend = (struct sgx_backend *)volume->private_data;

    buffer_manager_del(sgx_backend->buf_manager, metadata_uuid);

    return nexus_datastore_del_uuid(volume->metadata_store, metadata_uuid, NULL);
}

int
ocall_buffer_hardlink(struct nexus_uuid   * link_uuid,
                      struct nexus_uuid   * target_uuid,
                      struct nexus_volume * volume)
{
    return nexus_datastore_hardlink_uuid(volume->metadata_store,
                                         link_uuid,
                                         NULL,
                                         target_uuid,
                                         NULL);
}

int
ocall_buffer_rename(struct nexus_uuid   * from_uuid,
                    struct nexus_uuid   * to_uuid,
                    struct nexus_volume * volume)
{
    return nexus_datastore_rename_uuid(volume->metadata_store, from_uuid, NULL, to_uuid, NULL);
}
