#include "enclave_internal.h"

// the sealing key used in protecting volumekeys
void * global_backend_ext  = NULL;

struct supernode * global_supernode = NULL;

int
ecall_init_enclave(void * backend_info)
{
    global_backend_ext = backend_info;

    return 0;
}
