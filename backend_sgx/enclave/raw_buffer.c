#include "internal.h"

struct nexus_raw_buf {
    size_t size;

    struct nexus_uuid * buffer_uuid;
    uint8_t           * untrusted_addr;

    uint8_t           * trusted_addr;
};


struct nexus_raw_buf *
nexus_raw_buf_create(void * untrusted_addr, size_t size)
{
    struct nexus_raw_buf * raw_buf = NULL;

    raw_buf = nexus_malloc(sizeof(struct nexus_raw_buf));

    raw_buf->buffer_uuid = buffer_layer_create(untrusted_addr, size);
    if (raw_buf->buffer_uuid == NULL) {
        nexus_free(raw_buf);
        log_error("buffer_layer_create FAILED\n");
        return NULL;
    }

    raw_buf->untrusted_addr = untrusted_addr;
    raw_buf->size           = size;

    return raw_buf;
}

struct nexus_raw_buf *
nexus_raw_buf_new(size_t size)
{
    struct nexus_raw_buf * raw_buf = NULL;

    raw_buf = nexus_malloc(sizeof(struct nexus_raw_buf));

    raw_buf->size = size;

    return raw_buf;
}

void
nexus_raw_buf_free(struct nexus_raw_buf * raw_buf)
{
    if (raw_buf->buffer_uuid) {
        buffer_layer_free(raw_buf->buffer_uuid);
    }

    nexus_free(raw_buf);
}

uint8_t *
nexus_raw_buf_get(struct nexus_raw_buf * raw_buf)
{
    if (raw_buf->trusted_addr != NULL) {
        return raw_buf->trusted_addr;
    }

    if (raw_buf->untrusted_addr == NULL) {
        log_error("raw buffer untrusted_addr is NULL");
        return NULL;
    }

    raw_buf->trusted_addr = nexus_malloc(raw_buf->size);

    memcpy(raw_buf->trusted_addr, raw_buf->untrusted_addr, raw_buf->size);

    return raw_buf->trusted_addr;
}

int
nexus_raw_buf_put(struct nexus_raw_buf * raw_buf, uint8_t * trusted_addr)
{
    if (raw_buf->untrusted_addr == NULL) {
        raw_buf->buffer_uuid = buffer_layer_alloc(raw_buf->size, &raw_buf->untrusted_addr);

        if (raw_buf->buffer_uuid == NULL) {
            log_error("buffer_layer_alloc FAILED\n");
            return -1;
        }
    }

    memcpy(trusted_addr, raw_buf->untrusted_addr, raw_buf->size);

    return 0;
}
