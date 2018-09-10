#pragma once

#include <stdlib.h>
#include <stdbool.h>

struct nexus_ringbuf {
    void            * __buf;

    size_t            capacity;

    size_t            item_count;

    size_t            item_size;

    void            * head;
    void            * tail;
    void            * end;
};


struct nexus_ringbuf *
nexus_ringbuf_create(size_t item_size, size_t capacity);

void
nexus_ringbuf_destroy(struct nexus_ringbuf * ringbuf);

bool
nexus_ringbuf_enqueue(struct nexus_ringbuf * ringbuf, void * data);

bool
nexus_ringbuf_dequeue(struct nexus_ringbuf * ringbuf, void * dest);
