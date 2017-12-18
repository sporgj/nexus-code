#include "nexus_trusted.h"

sgx_key_128bit_t enclave_sealing_key;

// the user's identity
struct supernode * owner_supernode           = NULL;
struct volumekey * owner_supernode_volumekey = NULL;

// the public key of the authenticating user
static struct nexus_key * auth_user_pubkey      = NULL;
static struct pubkey_hash auth_user_pubkey_hash = { 0 };

// the nonce of the authentication challenge
static struct nexus_nonce auth_nonce = { 0 };

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
volumekey_from_rootuuid(struct nexus_uuid * root_uuid)
{
    return owner_supernode_volumekey;
}

static struct nexus_key *
copy_nexuskey_into_enclave(struct nexus_key * key_ext)
{
    struct nexus_key * key_copy = NULL;

    key_copy = (struct nexus_key *)calloc(1, sizeof(struct nexus_key));

    if (key_copy == NULL) {
        return NULL;
    }


    key_copy->data = (uint8_t *)calloc(1, key_ext->key_size);

    if (key_copy->data == NULL) {
        free(key_copy);
        return NULL;
    }


    key_copy->key_size = key_ext->key_size;
    memcpy(key_copy->data, key_ext->data, key_copy->key_size);

    return key_copy;
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
ecall_create_volume(struct nexus_uuid * supernode_uuid_ext,
                    struct nexus_uuid * root_uuid_ext,
                    struct nexus_key  * owner_pubkey_ext,
                    struct supernode  * supernode_buffer_ext,
                    struct dirnode    * dirnode_buffer_ext,
                    struct volumekey  * volume_volkey_ext)
{
    struct supernode * sealed_supernode = NULL;
    struct dirnode *   sealed_dirnode   = NULL;

    struct nexus_key * owner_pubkey = NULL;

    struct volumekey volumekey = { 0 };
    struct supernode supernode = { 0 };
    struct dirnode   dirnode   = { 0 };

    int ret = -1;



    // 1 -- Parse the public key string and initialize out structures
    owner_pubkey = copy_nexuskey_into_enclave(owner_pubkey_ext);

    if (owner_pubkey == NULL) {
        ocall_debug("could not copy key into enclave");
        return -1;
    }


    // 2 -- initialize the structures
    {
        struct supernode_header * supernode_header = &supernode.header;
        struct dirnode_header *   dirnode_header   = &dirnode.header;


        memcpy(&supernode_header->uuid,
               supernode_uuid_ext,
               sizeof(struct nexus_uuid));

        memcpy(&supernode_header->root_uuid,
               root_uuid_ext,
               sizeof(struct nexus_uuid));

        mbedtls_sha256(owner_pubkey->data,
                       owner_pubkey->key_size,
                       (uint8_t *)&supernode_header->owner,
                       0);

        supernode_header->total_size = sizeof(struct supernode);




        memcpy(&dirnode_header->uuid, root_uuid_ext, sizeof(struct nexus_uuid));

        memcpy(&dirnode_header->root_uuid,
               root_uuid_ext,
               sizeof(struct nexus_uuid));

        dirnode_header->total_size = sizeof(struct dirnode);
    }


    // 3 -- seal the structures
    {
        sgx_read_rand((uint8_t *)&volumekey, sizeof(crypto_ekey_t));

        if (supernode_encryption(&supernode, &volumekey, &sealed_supernode)) {
            ocall_debug("supernode sealage FAILED");
            goto out;
        }

        if (dirnode_encryption(&dirnode, NULL, &volumekey, &sealed_dirnode)) {
            ocall_debug("dirnode sealing FAILED");
            goto out;
        }

        if (volumekey_wrap(&volumekey)) {
            ocall_debug("volkey sealing FAILED");
            goto out;
        }
    }

    // copy out to untrusted memory
    memcpy(supernode_buffer_ext, sealed_supernode, sizeof(struct supernode));
    memcpy(dirnode_buffer_ext, sealed_dirnode, sizeof(struct dirnode));
    memcpy(volume_volkey_ext, &volumekey, sizeof(struct volumekey));

    ret = 0;
out:
    my_free(sealed_supernode);
    my_free(sealed_dirnode);
    my_free(owner_pubkey);

    return ret;
}

int
ecall_authentication_request(struct nexus_key   * user_pubkey,
                             struct nexus_nonce * challenge_nonce_ext)
{
    auth_user_pubkey = copy_nexuskey_into_enclave(user_pubkey);

    if (auth_user_pubkey == NULL) {
        ocall_debug("allocation error");
        return -1;
    }


    mbedtls_sha256(auth_user_pubkey->data,
                   auth_user_pubkey->key_size,
                   (uint8_t *)&auth_user_pubkey_hash,
                   0);


    // generate challenge and copy out
    sgx_read_rand((uint8_t *)&auth_nonce, sizeof(struct nexus_nonce));

    memcpy(challenge_nonce_ext, &auth_nonce, sizeof(struct nexus_nonce));

    return 0;
}

static int
nx_authentication_response(struct volumekey * sealed_volumekey,
                           struct supernode * sealed_supernode,
                           uint8_t *          signature,
                           size_t             signature_len)
{
    struct supernode * _supernode = NULL;
    struct volumekey * _volumekey = NULL;

    mbedtls_pk_context pk_context;

    uint8_t hash[CONFIG_HASH_BYTES] = { 0 };

    int ret = -1;


    mbedtls_pk_init(&pk_context);

    // sha256(nonce | supernode | volkey)
    {
        mbedtls_sha256_context sha_context;

        mbedtls_sha256_init(&sha_context);
        mbedtls_sha256_starts(&sha_context, 0);


        mbedtls_sha256_update(
            &sha_context, (uint8_t *)&auth_nonce, sizeof(struct nexus_nonce));

        mbedtls_sha256_update(&sha_context,
                              (uint8_t *)sealed_supernode,
                              sealed_supernode->header.total_size);

        mbedtls_sha256_update(&sha_context,
                              (uint8_t *)sealed_volumekey,
                              sizeof(struct volumekey));


        mbedtls_sha256_finish(&sha_context, hash);
        mbedtls_sha256_free(&sha_context);
    }



    // 1 - let's make sure our supernode is not tampered
    {
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

        ret = supernode_decryption(sealed_supernode, _volumekey, &_supernode);
        if (ret != 0) {
            ocall_debug("could not unseal supernode");
            goto out;
        }
    }



    // 2 - make sure hash(auth_user_pubkey) == supernode.owner
    {
        ret = memcmp(&auth_user_pubkey_hash,
                     &_supernode->header.owner,
                     sizeof(struct pubkey_hash));

        if (ret != 0) {
            ocall_debug("public key not matching owner's");
            goto out;
        }
    }



    // 3 - validate signature
    {
        ret = mbedtls_pk_parse_public_key(
            &pk_context, auth_user_pubkey->data, auth_user_pubkey->key_size);

        if (ret != 0) {
            ocall_debug("parsing public key failed");
            goto out;
        }

        ret = mbedtls_pk_verify(
            &pk_context, MBEDTLS_MD_SHA256, hash, 0, signature, signature_len);

        if (ret != 0) {
            ocall_debug("verifying signature failed");
            goto out;
        }
    }

    // update our login data structures
    owner_supernode           = _supernode;
    owner_supernode_volumekey = _volumekey;

    ret = 0;
out:
    mbedtls_pk_free(&pk_context);

    if (ret) {
        my_free(_supernode);
        my_free(_volumekey);
    }

    return ret;
}

int
ecall_authentication_response(struct volumekey * volumekey_ext,
                              struct supernode * supernode_ext,
                              uint8_t *          signature_ext,
                              size_t             signature_len)
{
    uint8_t * signature = NULL;

    struct supernode * supernode = NULL;
    struct volumekey   volumekey = { 0 };

    size_t supernode_size = 0;

    int ret = -1;

    // in case someone is trying to skip the challenge
    if (auth_user_pubkey == NULL) {
        ocall_debug("please request a challenge");
        return -1;
    }

    supernode_size = supernode_ext->header.total_size;

    supernode = (struct supernode *)calloc(1, supernode_size);
    signature = (uint8_t *)calloc(1, signature_len);

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
    my_free(auth_user_pubkey);
    memset_s(
        &auth_nonce, sizeof(struct nexus_nonce), 0, sizeof(struct nexus_nonce));

    return ret;
}
