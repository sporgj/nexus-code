#include "enclave_internal.h"

// the sealing key used in protecting volumekeys
void * global_backend_ext  = NULL;

// TODO: make this per-instance configurable
size_t global_chunk_size = NEXUS_CHUNK_SIZE;

int
ecall_init_enclave(void * backend_info)
{
    global_backend_ext = backend_info;

    if (nexus_vfs_init() != 0) {
        return -1;
    }

    return 0;
}
