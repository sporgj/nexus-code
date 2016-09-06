#include "enclave_t.h"
#include "../fileops.h"
#include "../types.h"

sgx_key_128bit_t __enclave_encryption_key__;

#include <mbedtls/aes.h>

void ecall_test_function(void) {

}

int ecall_init_enclave(void)
{
    sgx_key_request_t request;

    memset(&request, 0, sizeof(sgx_key_request_t));
    request.key_name = SGX_KEYSELECT_SEAL;
    request.key_policy = SGX_KEYPOLICY_MRSIGNER;
    request.attribute_mask.flags = 0xfffffffffffffff3ULL;
    request.attribute_mask.xfrm = 0;

    status = sgx_get_key(&request, &enclave_encryption_key);
    if (status != SGX_SUCCESS) {
        ret = ENCLAVE_ERROR_GET_KEY;
        goto out;
    }

out:
    return ret;
}

int ecall_crypt_function(fop_ctx_t * fop_ctx)
{
    mbedtls_aes_ctx aes_ctx;

    mbedtls_aes_init(&aes_ctx);


    mbedtls_aes_free(&aes_ctx);
}
