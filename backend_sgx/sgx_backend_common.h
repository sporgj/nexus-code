#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nexus_uuid.h>
#include <nexus_key.h>
#include <nexus_fs.h>

#define NONCE_SIZE 64

// XXX this is temporary
#define NEXUS_CHUNK_SIZE_LOG    20
#define NEXUS_CHUNK_SIZE        (1 << NEXUS_CHUNK_SIZE_LOG)

// raw pointer allows us to marshall arguments across the ecall boundary
struct raw_pointer {
    size_t size;
    void * addr;
};

struct nonce_challenge {
    uint8_t bytes[NONCE_SIZE];
};

struct nexus_stat_buffer {
    // TODO
};

// this will be used to transport keys across the enclave boundary
struct nexus_key_buffer {
    nexus_key_type_t key_type;

    size_t key_len;

    char * key_str;
};
