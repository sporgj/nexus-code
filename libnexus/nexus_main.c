#include "nexus_untrusted.h"

void
nexus_print_dirnode(struct dirnode * dirnode)
{

}

int
nexus_init_enclave(const char * enclave_fpath)
{
    int ret     = -1;
    int updated = 0;
    int err     = 0;

    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(enclave_fpath,
                             SGX_DEBUG_FLAG,
                             &token,
                             &updated,
                             &global_enclave_id,
                             NULL);
    if (ret != SGX_SUCCESS) {
        log_error("Could not open enclave: ret=%#x", ret);
        return -1;
    }

    ecall_init_enclave(global_enclave_id, &err);
    if (err != 0) {
        log_error("Initializing enclave failed");
        return -1;
    }

    return 0;
}

/**
 * Initializes the nexus subsystem
 */
int
nexus_init()
{

    return 0;
}
