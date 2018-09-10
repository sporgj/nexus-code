#pragma once

#include <nexus_uuid.h>

// represents the encrypted metadata object

struct metadata_object {
    struct nexus_uuid       uuid;

    uint8_t               * data_ptr;

    size_t                  data_len;
};
