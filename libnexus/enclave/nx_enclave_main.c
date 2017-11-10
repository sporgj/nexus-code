#include "nx_trusted.h"

sgx_key_128bit_t enclave_sealing_key;

// the public key of the authenticating user
static const char * auth_user_pubkey = NULL;

// the nonce of the authentication challenge
static nonce_t auth_nonce;

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
ecall_create_volume(struct uuid *       supernode_uuid_ext,
                    struct uuid *       root_uuid_ext,
                    const char *        publickey_str_in,
                    size_t              publickey_str_len,
                    uint8_t *           supernode_buffer_ext,
                    uint8_t *           dirnode_buffer_ext,
                    struct volume_key * volume_volkey_ext)
{
    int                ret       = -1;
    struct volume_key  volkey   = { 0 };
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

    sgx_read_rand((uint8_t *)&volkey, sizeof(crypto_ekey_t));

    memcpy(&supernode.header.uuid, supernode_uuid_ext, sizeof(struct uuid));
    memcpy(&supernode.header.root_uuid, root_uuid_ext, sizeof(struct uuid));
    mbedtls_sha256(publickey_str_in,
                   publickey_str_len,
                   (uint8_t *)&supernode.header.owner,
                   0);

    memcpy(&dirnode.header.uuid, root_uuid_in, sizeof(struct uuid));
    memcpy(&dirnode.header.root_uuid, root_uuid_in, sizeof(struct uuid));


    // seal the structures
    if (supernode_encrypt_and_seal(&supernode, &volkey)) {
        ocall_print("supernode sealage FAILED");
        goto out;
    }

    if (dirnode_encrypt_and_seal(&dirnode, &volkey)) {
        ocall_print("dirnode sealing FAILED");
        goto out;
    }

    if (volume_key_wrap(&volkey)) {
        ocall_print("volkey sealing FAILED");
        goto out;
    }

    // copy out to untrusted memory
    memcpy(supernode_buffer_ext, &supernode, sizeof(struct supernode));
    memcpy(dirnode_buffer_ext, &dirnode, sizeof(struct dirnode));
    memcpy(volume_volkey_ext, &volkey, sizeof(struct volume_key));

    ret = 0;
out:
    return ret;
}

// TODO
int
ecall_authentication_request(const char * publickey_str_in, nonce_t * nonce_out)
{
    // copy the publickey into the enclave

    // generate challenge and copy out

    return 0;
}

// TODO
int
ecall_authentication_response(crypto_ekey_t *    volume_volkey_in,
                              struct supernode * supernode_in,
                              uint8_t *          signature_in,
                              size_t             signature_len)
{
    // unseal volkey and verify supernode mac

    // make sure hash(auth_user_pubkey) == supernode.owner

    // validate signature

    return 0;
}
