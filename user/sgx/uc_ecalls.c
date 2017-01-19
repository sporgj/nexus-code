#include "enclave_private.h"
#include "seqptrmap.h"

sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;

auth_struct_t enclave_auth_data = {0};

int
ecall_init_enclave()
{
    sgx_report_t report;
#if 0
    /* uncomment this when ready to push */
    sgx_key_request_t request;
    sgx_status_t status;
    int ret;

    memset(&request, 0, sizeof(sgx_key_request_t));
    request.key_name = SGX_KEYSELECT_SEAL;
    request.key_policy = SGX_KEYPOLICY_MRSIGNER;
    request.attribute_mask.flags = 0xfffffffffffffff3ULL;
    request.attribute_mask.xfrm = 0;

    status = sgx_get_key(&request, &__enclave_encryption_key__);
    if (status != SGX_SUCCESS) {
        ret = E_ERROR_KEYINIT;
        goto out;
    }

    ret = E_SUCCESS;
out:
    return ret;
#endif

    /* lets generate our random nonce */
    sgx_read_rand(enclave_auth_data.nonce, sizeof(enclave_auth_data.nonce));
    if (sgx_create_report(NULL, NULL, &report) != SGX_SUCCESS) {
        return -1;
    }

    /* copy our enclave signature */
    memcpy(&enclave_auth_data.mrenclave, &report.body.mr_enclave,
           sizeof(sgx_measurement_t));

    memset(&__enclave_encryption_key__, 0, sizeof(sgx_key_128bit_t));
    return 0;
}

int
ecall_crypto_dirnode(dnode_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    return crypto_metadata(&header->crypto_ctx, header->protolen, data, op);
}

int
ecall_crypto_filebox(fbox_header_t * header, uint8_t * data, uc_crypto_op_t op)
{
    return crypto_metadata(&header->crypto_ctx, header->protolen, data, op);
}
