/**
 * Copyright (c) 2017, Judicael Djoko <jbriand@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 *
 *
 * Inspired from https://github.com/CCareaga/heap_allocator
 * by Copyright (c) 2017 Chris Careaga
 */
#pragma once

#include <stdint.h>
#include <stdlib.h>


#define MAX_BIN_COUNT           31 // can allocate up to 2^(MAX_BIN_count - 1)

#define MAX_BIN_INDEX           (MAX_BIN_COUNT - 1)

#define MIN_ALLOC_SIZE          4


struct __node;


typedef struct __bin {
    struct __node * head;
} bin_t;


struct nexus_heap {
    size_t          size;

    uint8_t       * start;

    uint8_t       * end;

    struct __bin    bins[MAX_BIN_COUNT];
};


void
nexus_heap_init(struct nexus_heap * heap, uint8_t * mem_ptr, size_t size);


void *
nexus_heap_malloc(struct nexus_heap * heap, size_t size);


void
nexus_heap_free(struct nexus_heap * heap, void * addr);
