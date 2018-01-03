#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nexus_uuid.h>
#include <nexus_key.h>

// TODO make untrusted_addr [0]
struct crypto_buffer {
    size_t    size;
    uint8_t * untrusted_addr;
};

// TODO make untrusted_addr [0]
struct raw_buffer {
    size_t size;
    void * untrusted_addr;
};

struct sealed_buffer {
    size_t  size;
    uint8_t untrusted_buffer[0];
};

struct nexus_stat_buffer {
    // TODO
};

// TEMPORARY
struct nexus_uuid_path {
    int count;
    struct nexus_uuid uuids[0];
};
