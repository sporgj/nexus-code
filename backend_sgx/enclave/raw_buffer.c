#include "internal.h"

struct raw_buffer *
raw_buffer_write(void * trusted_buffer, size_t size)
{
    struct raw_buffer * raw_buffer = NULL;

    int ret = -1;


    ret = ocall_calloc((void **) &raw_buffer, sizeof(struct raw_buffer));
    if (ret || !raw_buffer) {
        return NULL;
    }

    ret = ocall_calloc(&raw_buffer->untrusted_addr, size);
    if (ret || !raw_buffer->untrusted_addr) {
        ocall_free(raw_buffer);
        return NULL;
    }

    memcpy(raw_buffer->untrusted_addr, trusted_buffer, size);

    return raw_buffer;
}

// XXX this should be inlined in the header
void *
raw_buffer_get(struct raw_buffer * raw_buffer)
{
    return raw_buffer->untrusted_addr;
}


void
raw_buffer_init(struct raw_buffer * raw_buffer,
                void              * untrusted_addr,
                size_t              size)
{
    raw_buffer->untrusted_addr = untrusted_addr;
    raw_buffer->size = size;
}


void *
raw_buffer_read_trusted(struct raw_buffer * raw_buffer)
{
    void * ptr = nexus_malloc(raw_buffer->size);

    memcpy(ptr, raw_buffer->untrusted_addr, raw_buffer->size);

    return ptr;
}
