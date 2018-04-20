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
    return io_buffer_alloc(size, uuid, volume);
}

uint8_t *
ocall_buffer_get(struct nexus_uuid   * uuid,
                 nexus_io_flags_t       mode,
                 size_t              * p_size,
                 size_t              * p_timestamp,
                 struct nexus_volume * volume)
{

    return io_buffer_get(uuid, mode, p_size, p_timestamp, volume);
}

int
ocall_buffer_put(struct nexus_uuid * uuid, size_t * p_timestamp, struct nexus_volume * volume)
{
    return io_buffer_put(uuid, p_timestamp, volume);
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

int
ocall_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    struct nexus_stat stat_info;

    if (nexus_datastore_stat_uuid(volume->metadata_store, uuid, NULL, &stat_info)) {
        log_error("could not stat metadata file\n");
        return -1;
    }

    *timestamp = stat_info.timestamp;

    return 0;
}
