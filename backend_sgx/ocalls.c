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
ocall_buffer_put(struct nexus_uuid   * uuid,
                 uint8_t             * buffer,
                 size_t                size,
                 size_t              * timestamp,
                 struct nexus_volume * volume)
{
    return io_buffer_put(uuid, buffer, size, timestamp, volume);
}

int
ocall_buffer_lock(struct nexus_uuid   * metadata_uuid,
                  nexus_io_flags_t      flags,
                  struct nexus_volume * volume)
{
    return (io_buffer_lock(metadata_uuid, flags, volume) == NULL);
}

int
ocall_buffer_unlock(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    return (io_buffer_unlock(metadata_uuid, volume) == NULL);
}

int
ocall_buffer_new(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    return io_buffer_new(metadata_uuid, volume);
}

int
ocall_buffer_del(struct nexus_uuid * metadata_uuid, struct nexus_volume * volume)
{
    stash_manager_delete(metadata_uuid, volume);

    return io_buffer_del(metadata_uuid, volume);
}

int
ocall_buffer_stattime(struct nexus_uuid * uuid, size_t * timestamp, struct nexus_volume * volume)
{
    return io_buffer_stattime(uuid, timestamp, volume);
}



// stash management

int
ocall_versionstash_store(struct nexus_uuid   * uuid,
                         struct nexus_mac    * mac,
                         uint32_t              version,
                         struct nexus_volume * volume)
{
    return stash_manager_store(uuid, mac, version, volume);
}

int
ocall_versionstash_fetch(struct nexus_uuid   * uuid,
                         struct nexus_mac    * mac,
                         uint32_t            * version,
                         struct nexus_volume * volume)
{
    return stash_manager_fetch(uuid, mac, version, volume);
}

int
ocall_versionstash_delete(struct nexus_uuid * uuid, struct nexus_volume * volume)
{
    return stash_manager_delete(uuid, volume);
}
