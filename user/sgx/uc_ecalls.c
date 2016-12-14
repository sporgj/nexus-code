#include "enclave_private.h"
#include "seqptrmap.h"

sgx_key_128bit_t __TOPSECRET__ __enclave_encryption_key__;

int
ecall_init_enclave()
{
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
