#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <nexus_uuid.h>
#include <nexus_key.h>

// raw pointer allows us to marshall arguments across the ecall boundary
struct raw_pointer {
    size_t size;
    void * addr;
};

struct nexus_stat_buffer {
    // TODO
};

// TEMPORARY
struct nexus_uuid_path {
    int count;
    struct nexus_uuid uuids[0];
};
