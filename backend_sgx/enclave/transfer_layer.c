#include "enclave_internal.h"

// stores information about a particular transfer

struct xfer_context {
    struct nexus_data_buffer data_buffer;

    struct nexus_filebox * filebox;
};
