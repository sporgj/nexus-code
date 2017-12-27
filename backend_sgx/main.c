#include <stdlib.h>

#include <sgx_urts.h>

#include "internal.h"

#define DEFAULT_ENCLAVE_PATH "nexus_enclave.signed.so"

static int
init_enclave(const char * enclave_fpath, sgx_enclave_id_t * p_enclave_id)
{
    sgx_launch_token_t token = { 0 };

    int updated = 0;

    int ret = -1;

    /* initialize the enclave */
    ret = sgx_create_enclave(
        enclave_fpath, SGX_DEBUG_FLAG, &token, &updated, p_enclave_id, NULL);

    if (ret != SGX_SUCCESS) {
        log_error("Could not open enclave: ret=%#x", ret);
        return -1;
    }

    return 0;
}

static int
exit_enclave(sgx_enclave_id_t enclave_id)
{
    int ret = 0;

    log_debug("Destroying enclave (eid=%zu)", enclave_id);

    ret = sgx_destroy_enclave(enclave_id);

    return ret;
}


static void *
sgx_backend_init()
{
    struct sgx_backend_info * sgx_backend = NULL;

    sgx_backend = nexus_malloc(sizeof(struct sgx_backend_info));


    if (init_enclave(DEFAULT_ENCLAVE_PATH, &sgx_backend->enclave_id)) {
        log_error("nexus_init_enclave FAILED");
        nexus_free(sgx_backend);
        return NULL;
    }


    {
        int ret = -1;
        int err = -1;

        err = ecall_init_enclave(sgx_backend->enclave_id, &ret, sgx_backend);

        if (err || ret) {
            log_error("ecall_init_enclave() FAILED");

            exit_enclave(sgx_backend->enclave_id);

            nexus_free(sgx_backend);

            return NULL;
        }
    }

    return sgx_backend;
}

static int
sgx_backend_init_volume(struct nexus_volume * volume, void * priv_data)
{
#if 0
    struct sgx_backend_info * sgx_backend = NULL;

    struct nexus_uuid supernode_uuid;

    struct nexus_raw_key * volumekey_sealed = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend_info *)priv_data;


    // call the enclave


    ret = 0;
out:
    if (err || ret) {
        if (volumekey_sealed) {
            nexus_free(volumekey_sealed);
        }
    }

    return ret;
#endif
    return -1;
}

static struct nexus_backend_impl sgx_backend_impl = {
    .name            = "SGX",
    .init            = sgx_backend_init,
    .init_volume     = sgx_backend_init_volume
};


nexus_register_backend(sgx_backend_impl);
