#include "nx_trusted.h"

sgx_key_128bit_t enclave_sealing_key;

// the user's identity
struct supernode *  owner_supernode           = NULL;
struct volumekey * owner_supernode_volumekey = NULL;

// the public key of the authenticating user
static char *             auth_user_pubkey      = NULL;
static size_t             auth_user_pubkey_len  = 0;
static struct pubkey_hash auth_user_pubkey_hash = { 0 };

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
                    struct supernode *  supernode_buffer_ext,
                    struct dirnode *    dirnode_buffer_ext,
                    struct volumekey * volume_volkey_ext)
{
    int                ret       = -1;
    struct volumekey  volkey   = { 0 };
    struct supernode   supernode = { 0 };
    struct dirnode     dirnode   = { 0 };
    mbedtls_pk_context pk;

    // 1 -- Parse the public key string and initialize out structures
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_key(&pk, publickey_str_in, publickey_str_len);
    if (ret != 0) {
        ocall_debug("mbedtls_pk_parse_public_key FAILED");
        goto out;
    }

    sgx_read_rand((uint8_t *)&volkey, sizeof(crypto_ekey_t));

    memcpy(&supernode.header.uuid, supernode_uuid_ext, sizeof(struct uuid));
    memcpy(&supernode.header.root_uuid, root_uuid_ext, sizeof(struct uuid));
    mbedtls_sha256(publickey_str_in,
                   publickey_str_len,
                   (uint8_t *)&supernode.header.owner,
                   0);
    supernode.header.total_size = sizeof(struct supernode);

    memcpy(&dirnode.header.uuid, root_uuid_ext, sizeof(struct uuid));
    memcpy(&dirnode.header.root_uuid, root_uuid_ext, sizeof(struct uuid));
    dirnode.header.total_size = sizeof(struct dirnode);


    // seal the structures
    if (supernode_encrypt_and_seal(&supernode, &volkey)) {
        ocall_debug("supernode sealage FAILED");
        goto out;
    }

    if (dirnode_encrypt_and_seal(&dirnode, &volkey)) {
        ocall_debug("dirnode sealing FAILED");
        goto out;
    }

    if (volumekey_wrap(&volkey)) {
        ocall_debug("volkey sealing FAILED");
        goto out;
    }

    // copy out to untrusted memory
    memcpy(supernode_buffer_ext, &supernode, sizeof(struct supernode));
    memcpy(dirnode_buffer_ext, &dirnode, sizeof(struct dirnode));
    memcpy(volume_volkey_ext, &volkey, sizeof(struct volumekey));

    ret = 0;
out:
    return ret;
}

// TODO
int
ecall_authentication_request(const char * publickey_str_in,
                             size_t       publickey_str_len,
                             nonce_t *    nonce_ext)
{
    // copy the publickey into the enclave
    auth_user_pubkey = strndup(publickey_str_in, publickey_str_len);
    if (auth_user_pubkey == NULL) {
        ocall_debug("allocation error");
        return -1;
    }

    auth_user_pubkey_len = publickey_str_len;
    mbedtls_sha256(auth_user_pubkey,
                   auth_user_pubkey_len,
                   (uint8_t *)&auth_user_pubkey_hash,
                   0);

    // generate challenge and copy out
    sgx_read_rand((uint8_t *)&auth_nonce, sizeof(nonce_t));

    memcpy(nonce_ext, auth_nonce, sizeof(nonce_t));

    return 0;
}

int
nx_authentication_response(struct volumekey * _volumekey,
                           struct supernode *  _supernode,
                           uint8_t *           signature,
                           size_t              signature_len)
{
    int                    ret                     = -1;
    uint8_t                hash[CONFIG_HASH_BYTES] = { 0 };
    mbedtls_sha256_context sha_ctx;
    mbedtls_pk_context     pk;

    mbedtls_sha256_init(&sha_ctx);
    mbedtls_pk_init(&pk);

    // sha256(nonce | supernode | volkey)
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, (uint8_t *)&auth_nonce, sizeof(nonce_t));
    mbedtls_sha256_update(
            &sha_ctx, (uint8_t *)_supernode, _supernode->header.total_size);
    mbedtls_sha256_update(
            &sha_ctx, (uint8_t *)_volumekey, sizeof(struct volumekey));
    mbedtls_sha256_finish(&sha_ctx, hash);


    // 1 - let's make sure our supernode is not tampered
    if (volumekey_unwrap(_volumekey)) {
        ocall_debug("unwrapping volume key failed");
        goto out;
    }

    if (supernode_decrypt_and_unseal(_supernode, _volumekey)) {
        ocall_debug("could not unseal supernode");
        goto out;
    }

    // 2 - make sure hash(auth_user_pubkey) == supernode.owner
    if (memcmp(&auth_user_pubkey_hash,
               &_supernode->header.owner,
               sizeof(struct pubkey_hash))) {
        ocall_debug("public key not matching owner's");
        goto out;
    }

    // 3 - validate signature
    ret = mbedtls_pk_parse_public_key(
            &pk, auth_user_pubkey, auth_user_pubkey_len);
    if (ret != 0) {
        ocall_debug("parsing public key failed");
        goto out;
    }

    ret = mbedtls_pk_verify(
        &pk, MBEDTLS_MD_SHA256, hash, 0, signature, signature_len);
    if (ret != 0) {
        ocall_debug("verifying signature failed");
        goto out;
    }

    // update our login data structures
    owner_supernode           = _supernode;
    owner_supernode_volumekey = _volumekey;

    ret = 0;
out:
    mbedtls_sha256_free(&sha_ctx);
    mbedtls_pk_free(&pk);

    return ret;
}

// TODO
int
ecall_authentication_response(struct volumekey * volumekey_ext,
                              struct supernode *  supernode_ext,
                              uint8_t *           signature_ext,
                              size_t              signature_len)
{
    int                 ret            = -1;
    uint8_t *           signature      = NULL;
    struct supernode *  _supernode     = NULL;
    struct volumekey * _volumekey     = NULL;
    size_t              supernode_size = supernode_ext->header.total_size;

    // in case someone is trying to skip the challenge
    if (auth_user_pubkey == NULL) {
        ocall_debug("please request a challenge");
        return -1;
    }

    _volumekey = (struct volumekey *)calloc(1, sizeof(struct volumekey));
    _supernode = (struct supernode *)calloc(1, supernode_size);
    signature  = (uint8_t *)calloc(1, signature_len);

    if (_volumekey == NULL || _supernode == NULL || signature == NULL) {
        ocall_debug("allocation failed");
        goto out;
    }

    // copy in the data structures and call nx_authentication_response()
    memcpy(_volumekey, volumekey_ext, sizeof(struct volumekey));
    memcpy(_supernode, supernode_ext, supernode_size);
    memcpy(signature, signature_ext, signature_len);

    ret = nx_authentication_response(
        _volumekey, _supernode, signature, signature_len);

out:
    if (ret) {
        my_free(_volumekey);
        my_free(_supernode);
    }

    my_free(signature);

    // let's cleanup all authentication data
    auth_user_pubkey_len = 0;
    my_free(auth_user_pubkey);
    memset_s(&auth_nonce, sizeof(nonce_t), 0, sizeof(nonce_t));

    return ret;
}
