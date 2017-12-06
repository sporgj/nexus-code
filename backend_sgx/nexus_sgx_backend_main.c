#include <stdlib.h>

#include <sgx_urts.h>

#include <nexus_backend.h>
#include "nexus_log.h"
#include "nexus_enclave_u.h"

#define ENCLAVE_PATH "nexus_enclave.signed.so"

sgx_enclave_id_t global_enclave_id = 0;

void
ocall_print(const char * str)
{
    printf("%s", str);
    fflush(stdout);
}


void *
ocall_calloc(size_t size)
{
    return calloc(1, size);
}

static int
nexus_init_enclave(const char * enclave_fpath)
{
    int ret     = -1;
    int updated = 0;
    int err     = 0;

    /* initialize the enclave */
    sgx_launch_token_t token = {0};
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

static int
nexus_exit_enclave()
{
    int ret = 0;

    if (global_enclave_id) {
        log_debug("Destroying enclave (eid=%zu)", global_enclave_id);
        ret = sgx_destroy_enclave(global_enclave_id);
    }

    global_enclave_id = 0;

    return ret;
}

// TODO temporary, add this at config
int
nexus_init_backend()
{
    return nexus_init_enclave(ENCLAVE_PATH);
}

int
nexus_exit_backend()
{
    return nexus_exit_enclave(global_enclave_id);
}
