#include <string.h>

#include "nexus_ringbuf.h"
#include "nexus_util.h"


struct nexus_ringbuf *
nexus_ringbuf_create(size_t item_size, size_t capacity)
{
    struct nexus_ringbuf * ringbuf = nexus_malloc(sizeof(struct nexus_ringbuf));

    size_t total_size  = item_size * capacity;


    ringbuf->__buf     = nexus_malloc(total_size);

    ringbuf->capacity  = capacity;
    ringbuf->item_size = item_size;

    ringbuf->head      = ringbuf->__buf;
    ringbuf->tail      = ringbuf->__buf;
    ringbuf->end       = ringbuf->__buf + total_size;

    return ringbuf;
}

void
nexus_ringbuf_destroy(struct nexus_ringbuf * ringbuf)
{
    nexus_free(ringbuf->__buf);
    nexus_free(ringbuf);
}

bool
nexus_ringbuf_enqueue(struct nexus_ringbuf * ringbuf, void * data)
{
    if (ringbuf->item_count == ringbuf->capacity) {
        return false;
    }

    memcpy(ringbuf->tail, data, ringbuf->item_size);

    ringbuf->tail = (char *) ringbuf->tail + ringbuf->item_size;

    if (ringbuf->tail == ringbuf->end) {
        ringbuf->tail = ringbuf->__buf;
    }

    ringbuf->item_count += 1;

    return true;
}

bool
nexus_ringbuf_dequeue(struct nexus_ringbuf * ringbuf, void * dest)
{
    if (ringbuf->item_count == 0) {
        return false;
    }

    memcpy(dest, ringbuf->head, ringbuf->item_size);

    ringbuf->head = (char *) ringbuf->head + ringbuf->item_size;

    if (ringbuf->head == ringbuf->end) {
        ringbuf->head = ringbuf->__buf;
    }

    ringbuf->item_count -= 1;

    return true;
}
