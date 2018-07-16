#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nexus_volume.h>
#include <nexus_uuid.h>
#include <nexus_key.h>
#include <nexus_fs.h>
#include <nexus_heap.h>
#include <nexus_ringbuf.h>

#define NONCE_SIZE 64

// XXX this is temporary
#define NEXUS_CHUNK_SIZE_LOG    20
#define NEXUS_CHUNK_SIZE        (1 << NEXUS_CHUNK_SIZE_LOG)

struct nonce_challenge {
    uint8_t bytes[NONCE_SIZE];
};


// this will be used to transport keys across the enclave boundary
struct nexus_key_buffer {
    nexus_key_type_t key_type;

    size_t key_len;

    char * key_str;
};


// displaying the write buffer
struct nexus_ioreq {
    struct nexus_uuid   uuid;

    size_t              buflen;
    uint8_t           * buffer;

    bool                completed;

    size_t              timestamp;
};


struct nexus_iochan {
    struct nexus_ringbuf * dirty; // list of dirty requests

    struct nexus_ringbuf * clean; // list of completed requests
};
