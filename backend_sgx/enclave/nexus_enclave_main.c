#include "nexus_trusted.h"

sgx_key_128bit_t enclave_sealing_key;

// the user's identity
struct supernode * owner_supernode           = NULL;
struct volumekey * owner_supernode_volumekey = NULL;

// the public key of the authenticating user
static char *             auth_user_pubkey      = NULL;
static size_t             auth_user_pubkey_len  = 0;
static struct pubkey_hash auth_user_pubkey_hash = { 0 };

// the nonce of the authentication challenge
static nonce_t auth_nonce;

size_t                        dirnode_cache_size = 0;
struct dirnode_wrapper_list * dirnode_cache      = NULL;

/**
 * returns the volumekey corresponding to the root uuid.
 *
 * TODO: for now, let's just return the owner_supernode_volumekey. In the
 * future, once multivolume support is added, we shall iterate a list.
 *
 * @param root_uuid is the root_uuid to search with
 * @return NULL if volume key not found.
 */
struct volumekey *
volumekey_from_rootuuid(struct uuid * root_uuid)
{
    return owner_supernode_volumekey;
}

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

    // allocate our enclave variables
    dirnode_cache = (struct dirnode_wrapper_list *)calloc(
        1, sizeof(struct dirnode_wrapper_list));

    if (dirnode_cache == NULL) {
        ocall_debug("allocation error");
        return -1;
    }

    TAILQ_INIT(dirnode_cache);

    return 0;
}

int
ecall_create_volume(struct uuid *      supernode_uuid_ext,
                    struct uuid *      root_uuid_ext,
                    const char *       publickey_str_in,
                    size_t             publickey_str_len,
                    struct supernode * supernode_buffer_ext,
                    struct dirnode *   dirnode_buffer_ext,
                    struct volumekey * volume_volkey_ext)
{
    int                ret              = -1;
    struct supernode * sealed_supernode = NULL;
    struct dirnode *   sealed_dirnode   = NULL;
    struct volumekey   volkey           = { 0 };
    struct supernode   supernode        = { 0 };
    struct dirnode     dirnode          = { 0 };
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
    if (supernode_encryption1(&supernode, &volkey, &sealed_supernode)) {
        ocall_debug("supernode sealage FAILED");
        goto out;
    }

    if (dirnode_encryption1(NULL, &dirnode, &volkey, &sealed_dirnode)) {
        ocall_debug("dirnode sealing FAILED");
        goto out;
    }

    if (volumekey_wrap(&volkey)) {
        ocall_debug("volkey sealing FAILED");
        goto out;
    }

    // copy out to untrusted memory
    memcpy(supernode_buffer_ext, sealed_supernode, sizeof(struct supernode));
    memcpy(dirnode_buffer_ext, sealed_dirnode, sizeof(struct dirnode));
    memcpy(volume_volkey_ext, &volkey, sizeof(struct volumekey));

    ret = 0;
out:
    my_free(sealed_supernode);
    my_free(sealed_dirnode);

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
nx_authentication_response(struct volumekey * sealed_volumekey,
                           struct supernode * sealed_supernode,
                           uint8_t *          signature,
                           size_t             signature_len)
{
    int                    ret                     = -1;
    uint8_t                hash[CONFIG_HASH_BYTES] = { 0 };
    struct supernode *     _supernode              = NULL;
    struct volumekey *     _volumekey              = NULL;
    mbedtls_sha256_context sha_ctx;
    mbedtls_pk_context     pk;

    mbedtls_sha256_init(&sha_ctx);
    mbedtls_pk_init(&pk);

    // sha256(nonce | supernode | volkey)
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, (uint8_t *)&auth_nonce, sizeof(nonce_t));
    mbedtls_sha256_update(&sha_ctx,
                          (uint8_t *)sealed_supernode,
                          sealed_supernode->header.total_size);
    mbedtls_sha256_update(
        &sha_ctx, (uint8_t *)sealed_volumekey, sizeof(struct volumekey));
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    // 1 - let's make sure our supernode is not tampered
    _volumekey = (struct volumekey *)calloc(1, sizeof(struct volumekey));
    if (_volumekey == NULL) {
        ocall_debug("allocation error");
        return -1;
    }

    memcpy(_volumekey, sealed_volumekey, sizeof(struct volumekey));

    if (volumekey_unwrap(_volumekey)) {
        ocall_debug("unwrapping volume key failed");
        goto out;
    }

    ret = supernode_decryption1(
        sealed_supernode, _volumekey, &_supernode);
    if (ret != 0) {
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
    mbedtls_pk_free(&pk);

    if (ret) {
        my_free(_supernode);
        my_free(_volumekey);
    }

    return ret;
}

// TODO
int
ecall_authentication_response(struct volumekey * volumekey_ext,
                              struct supernode * supernode_ext,
                              uint8_t *          signature_ext,
                              size_t             signature_len)
{
    int                ret            = -1;
    size_t             supernode_size = 0;
    uint8_t *          signature      = NULL;
    struct supernode * supernode      = NULL;
    struct volumekey   volumekey      = { 0 };

    // in case someone is trying to skip the challenge
    if (auth_user_pubkey == NULL) {
        ocall_debug("please request a challenge");
        return -1;
    }

    supernode_size = supernode_ext->header.total_size;

    supernode = (struct supernode *)calloc(1, supernode_size);
    signature  = (uint8_t *)calloc(1, signature_len);

    if (supernode == NULL || signature == NULL) {
        ocall_debug("allocation failed");
        goto out;
    }

    // copy in the data structures and call nx_authentication_response()
    memcpy(&volumekey, volumekey_ext, sizeof(struct volumekey));
    memcpy(supernode, supernode_ext, supernode_size);
    memcpy(signature, signature_ext, signature_len);

    ret = nx_authentication_response(
        &volumekey, supernode, signature, signature_len);

out:
    my_free(supernode);
    my_free(signature);

    // let's cleanup all authentication data
    auth_user_pubkey_len = 0;
    my_free(auth_user_pubkey);
    memset_s(&auth_nonce, sizeof(nonce_t), 0, sizeof(nonce_t));

    return ret;
}
