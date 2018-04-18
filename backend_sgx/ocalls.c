#include "internal.h"

#include "io.c"

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
ocall_buffer_flush(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    struct nexus_locked_file * locked_file = lock_manager_get(sgx_backend->lock_manager, uuid);

    if (locked_file == NULL) {
        log_error("could not find file in lock manager\n");
        return -1;
    }


    // write the contents
    {
        struct __buf * buf = NULL;

        int ret = -1;


        buf = buffer_manager_get(sgx_backend->buf_manager, uuid);

        if (buf == NULL) {
            log_error("buffer_manager_get returned NULL\n");
            return -1;
        }

        ret = nexus_datastore_write_uuid(volume->metadata_store, locked_file, buf->addr, buf->size);

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
ocall_buffer_get(struct nexus_uuid   * uuid,
                 nexus_io_mode_t       mode,
                 size_t              * p_size,
                 struct nexus_volume * volume)
{

    return io_buffer_get(uuid, mode, p_size, volume);
}

int
ocall_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    return nexus_datastore_new_uuid(volume->metadata_store, metadata_uuid, NULL);
}

int
ocall_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)volume->private_data;

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
