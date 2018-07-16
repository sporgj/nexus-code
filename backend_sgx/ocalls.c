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
ocall_buffer_get(struct nexus_uuid   * uuid,
                 nexus_io_flags_t       mode,
                 size_t              * p_size,
                 size_t              * p_timestamp,
                 struct nexus_volume * volume)
{
    return io_buffer_get(uuid, mode, p_size, p_timestamp, volume);
}

int
ocall_buffer_lock(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    return (io_buffer_lock(metadata_uuid, volume) == NULL);
}

int
ocall_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    return io_buffer_new(metadata_uuid, volume);
}

int
ocall_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    return io_buffer_del(metadata_uuid, volume);
}

int
ocall_buffer_hardlink(struct nexus_uuid   * link_uuid,
                      struct nexus_uuid   * target_uuid,
                      struct nexus_volume * volume)
{
    return io_buffer_hardlink(link_uuid, target_uuid, volume);
}

int
ocall_buffer_rename(struct nexus_uuid   * from_uuid,
                    struct nexus_uuid   * to_uuid,
                    struct nexus_volume * volume)
{
    return io_buffer_rename(from_uuid, to_uuid, volume);
}

int
ocall_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    return io_buffer_stattime(uuid, timestamp, volume);
}
