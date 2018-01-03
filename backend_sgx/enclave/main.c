#include "internal.h"

// the sealing key used in protecting volumekeys
sgx_key_128bit_t global_enclave_sealing_key = { 0 };

void * global_backend_ext  = NULL;

int
ecall_init_enclave(void * backend_info)
{
    // initialize the enclave_sealing_key
    {
        sgx_key_request_t request = { 0 };
        sgx_report_t      report;
        sgx_status_t      status;

        request.key_name             = SGX_KEYSELECT_SEAL;
        request.key_policy           = SGX_KEYPOLICY_MRSIGNER;
        request.attribute_mask.flags = 0xfffffffffffffff3ULL;
        request.attribute_mask.xfrm  = 0;

        status = sgx_get_key(&request, &global_enclave_sealing_key);
        if (status != SGX_SUCCESS) {
            return -1;
        }
    }

    global_backend_ext = backend_info;

    return 0;
}
