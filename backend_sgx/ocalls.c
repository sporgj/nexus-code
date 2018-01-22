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
}



// ------------------- Buffer Management ---------------------------

uint8_t *
ocall_buffer_alloc(size_t size, struct nexus_uuid * dest_buffer_uuid)
{
    return buffer_manager_alloc(size, dest_buffer_uuid);
}

uint8_t *
ocall_buffer_get(struct nexus_uuid * buffer_uuid, size_t * p_buffer_size)
{
    return buffer_manager_get(buffer_uuid, p_buffer_size);
}

void
ocall_buffer_free(struct nexus_uuid * buffer_uuid)
{
    buffer_manager_free(buffer_uuid);
}
