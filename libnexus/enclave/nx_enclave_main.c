#include "nx_trusted.h"

sgx_key_128bit_t enclave_sealing_key;

int
ecall_init_enclave()
{
    sgx_key_request_t request = { 0 };
    sgx_report_t      report;
    sgx_status_t      status;

    request.key_name             = SGX_KEYSELECT_SEAL;
    request.key_policy           = SGX_KEYPOLICY_MRSIGNER;
    request.attribute_mask.flags = 0xfffffffffffffff3ULL;
    request.attribute_mask.xfrm  = 0;

    status = sgx_get_key(&request, &enclave_sealing_key);
    if (status != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

int
ecall_create_volume(struct uuid * supernode_uuid_in,
                    struct uuid * root_uuid_in,
                    const char *  publickey_str_in,
                    size_t        publickey_str_len,
                    uint8_t *     supernode_buffer_out,
                    uint8_t *     dirnode_buffer_out,
                    crypto_ekey_t * volume_rootkey_out)
{
    int                ret       = -1;
    crypto_ekey_t      rootkey   = { 0 };
    struct supernode   supernode = { 0 };
    struct dirnode     dirnode   = { 0 };
    mbedtls_pk_context pk;

    // 1 -- Parse the public key string and initialize out structures
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_key(&pk, publickey_str_in, publickey_str_len);
    if (ret != 0) {
        ocall_print("mbedtls_pk_parse_public_key FAILED");
        goto out;
    }

    sgx_read_rand((uint8_t *)&rootkey, sizeof(crypto_ekey_t));

    memcpy(&supernode.uuid, supernode_uuid_in, sizeof(struct uuid));
    memcpy(&supernode.root_uuid, root_uuid_in, sizeof(struct uuid));
    mbedtls_sha256(
        publickey_str_in, publickey_str_len, (uint8_t *)&supernode.owner, 0);

    memcpy(&dirnode.uuid, root_uuid_in, sizeof(struct uuid));
    memcpy(&dirnode.root_uuid, root_uuid_in, sizeof(struct uuid));


    // seal the structures
    if (supernode_encrypt_and_seal(&supernode, &rootkey)) {
        ocall_print("supernode sealage FAILED");
        goto out;
    }

    if (dirnode_encrypt_and_seal(&dirnode, &rootkey)) {
        ocall_print("dirnode sealing FAILED");
        goto out;
    }

    if (volume_rootkey_wrap(&rootkey)) {
        ocall_print("rootkey sealing FAILED");
        goto out;
    }


    // copy out to untrusted memory
    memcpy(supernode_buffer_out, &supernode, sizeof(struct supernode));
    memcpy(dirnode_buffer_out, &dirnode, sizeof(struct dirnode));
    memcpy(volume_rootkey_out, &rootkey, sizeof(crypto_ekey_t));

    ret = 0;
out:
    return ret;
}
