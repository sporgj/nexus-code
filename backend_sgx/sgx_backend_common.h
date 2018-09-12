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

#include "tweetnacl.h"

#define NONCE_SIZE 64

// XXX this is temporary
#define NEXUS_CHUNK_SIZE_LOG    20
#define NEXUS_CHUNK_SIZE        (1 << NEXUS_CHUNK_SIZE_LOG)

struct nonce_challenge {
    uint8_t bytes[NONCE_SIZE];
};


// used for the instance creation
struct ecdh_public_key {
    uint8_t  bytes[crypto_box_PUBLICKEYBYTES];
} __attribute__((packed));

struct ecdh_nonce {
    uint8_t  bytes[crypto_box_NONCEBYTES];
} __attribute__((packed));


#define MAX_DIRENT_REQUESTS     20

enum fs_op_type;


// this will be used to transport keys across the enclave boundary
struct nexus_key_buffer {
    nexus_key_type_t key_type;

    size_t key_len;

    char * key_str;
};


#if 0
struct nexus_fsop_req {
    size_t                  req_id;

    enum fs_op_type         type;

    bool                    completed; // done by the untrusted portion

    bool                    _ack; // done by the enclave

    struct nexus_ringbuf *  dirent_requests;


    struct list_head        node;
};

struct nexus_ioreq {
    struct nexus_uuid   uuid;

    size_t              buflen;
    uint8_t           * buffer;

    bool                completed;

    size_t              timestamp;
};


struct nexus_dirent_req {
    struct nexus_dirent dirent;
    struct nexus_uuid   uuid;
} __attribute__((packed));

struct nexus_iochan {
    struct nexus_ringbuf * dirty; // list of dirty requests

    struct nexus_ringbuf * clean; // list of completed requests
};
#endif
