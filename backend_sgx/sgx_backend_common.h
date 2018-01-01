#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nexus_uuid.h>
#include <nexus_key.h>

struct crypto_buffer {
    size_t    size;
    uint8_t * untrusted_addr;
};

struct nexus_raw_buffer {
    size_t    buflen;
    uint8_t * buffer;
};

struct nexus_stat_buffer {
    // TODO
};

// TEMPORARY
struct nexus_uuid_path {
    int count;
    struct nexus_uuid uuids[0];
};
