#include "enclave_internal.h"

// the sealing key used in protecting volumekeys
void * global_backend_ext  = NULL;

// TODO: make this per-instance configurable
size_t global_chunk_size = NEXUS_CHUNK_SIZE;

size_t global_log2chunk_size = 0;

int
ecall_init_enclave(void * backend_info)
{
    global_backend_ext = backend_info;

    if (nexus_vfs_init() != 0) {
        return -1;
    }

    {
        size_t temp = global_chunk_size;
        size_t pow2 = 0;

        while (temp > 0) {
            pow2 += 1;
            temp >>= 1;
        }

        global_log2chunk_size = pow2 - 1;
    }

    return 0;
}
