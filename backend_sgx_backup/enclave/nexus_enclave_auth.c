#include "nexus_trusted.h"

static bool                   has_requested_challenge = false;

static struct nexus_raw_key * auth_pubkey             = NULL;
static struct pubkey_hash     auth_pubkey_hash        = { 0 };

static struct volumekey       auth_volumekey_sealed   = { 0 };
static struct volumekey       auth_volumekey_unsealed = { 0 };

static struct nexus_nonce     auth_nonce              = { 0 };

int
ecall_authentication_request(struct nexus_key   * user_pubkey_in,
                             struct volumekey   * volumekey,
                             struct nexus_nonce * challenge_out)
{
    memcpy(&auth_volumekey_sealed, volumekey, sizeof(struct volumekey));
    memcpy(&auth_volumekey_unsealed, volumekey, sizeof(struct volumekey));

    if (volumekey_unwrap(&auth_volumekey_unsealed)) {
        ocall_debug("unwrapping volume key failed");
        goto out;
    }

    // in case a previous request wasn't responded
    if (auth_pubkey != NULL) {
        my_free(auth_pubkey);
    }

    auth_pubkey = copy_nexuskey_into_enclave(user_pubkey);
    if (auth_pubkey == NULL) {
        ocall_debug("allocation error");
        return -1;
    }

    mbedtls_sha256(auth_pubkey->data,
                   auth_pubkey->key_size,
                   (uint8_t *)&auth_pubkey_hash,
                   0);

    has_requested_challenge = true;



    // generate challenge and copy out
    sgx_read_rand((uint8_t *)&auth_nonce, sizeof(struct nexus_nonce));

    memcpy(challenge_out, &auth_nonce, sizeof(struct nexus_nonce));

    return 0;
}

static int
verify_response(struct supernode * sealed_supernode,
                uint8_t          * signature,
                size_t             signature_len)
{
    struct supernode * supernode = NULL;

    mbedtls_pk_context pk_context;

    uint8_t hash[CONFIG_HASH_BYTES] = { 0 };

    int ret = -1;


    mbedtls_pk_init(&pk_context);

    // sha256(nonce | supernode | volkey)
    {
        mbedtls_sha256_context sha_context;

        mbedtls_sha256_init(&sha_context);
        mbedtls_sha256_starts(&sha_context, 0);

        mbedtls_sha256_update(&sha_context,
                              (uint8_t *)&authentication_nonce,
                              sizeof(struct nexus_nonce));

        mbedtls_sha256_update(&sha_context,
                              (uint8_t *)sealed_supernode,
                              sealed_supernode->header.total_size);

        mbedtls_sha256_update(&sha_context,
                              (uint8_t *)&auth_volumekey_sealed,
                              sizeof(struct volumekey));


        mbedtls_sha256_finish(&sha_context, hash);
        mbedtls_sha256_free(&sha_context);
    }



    // 1 - let's make sure our supernode is not tampered
    {
        ret = supernode_decryption(
            sealed_supernode, &auth_volumekey_unsealed, &_supernode);

        if (ret != 0) {
            ocall_debug("could not unseal supernode");
            goto out;
        }
    }



    // 2 - make sure hash(authentication_pubkey) == supernode.owner
    {
        ret = memcmp(&auth_pubkey_hash,
                     &_supernode->header.owner,
                     sizeof(struct pubkey_hash));

        if (ret != 0) {
            ocall_debug("public key not matching owner's");
            goto out;
        }
    }



    // 3 - validate signature
    {
        ret = mbedtls_pk_parse_public_key(&pk_context,
                                          authentication_pubkey->data,
                                          authentication_pubkey->key_size);

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
    ret = volumes_add_supernode(_supernode, &auth_volumekey_unsealed);
out:
    mbedtls_pk_free(&pk_context);

    if (ret) {
        my_free(_supernode);
    }

    return ret;
}

int
ecall_authentication_response(struct supernode * supernode_in,
                              uint8_t *          signature_in,
                              size_t             signature_len)
{
    uint8_t * signature = NULL;

    struct supernode * supernode = NULL;

    int ret = -1;


    // in case someone is trying to skip the challenge
    if (has_requested_challenge == false) {
        ocall_debug("please request a challenge");
        return -1;
    }


    signature = (uint8_t *)calloc(1, signature_len);

    supernode = supernode_copy_whole(supernode_in);

    if (supernode == NULL || signature == NULL) {
        ocall_debug("allocation failed");
        goto out;
    }


    memcpy(signature, signature_ext, signature_len);

    // copy in the data structures and call nx_authentication_response()

    ret = verify_response(supernode, signature, signature_len);

out:
    my_free(supernode);
    my_free(signature);

    // let's cleanup all authentication data
    has_requested_challenge = true;

    my_free(authentication_pubkey);

    memset_s(&authentication_nonce,
             sizeof(struct nexus_nonce),
             0,
             sizeof(struct nexus_nonce));

    return ret;
}

static struct nexus_raw_key *
copy_nexuskey_into_enclave(struct nexus_raw_key * key_ext)
{
    struct nexus_raw_key * key_copy = NULL;

    key_copy = (struct nexus_raw_key *)calloc(1, sizeof(struct nexus_raw_key));

    if (key_copy == NULL) {
        return NULL;
    }


    key_copy->key_data = (uint8_t *)calloc(1, key_ext->key_size);

    if (key_copy->key_data == NULL) {
        free(key_copy);
        return NULL;
    }


    key_copy->key_size = key_ext->key_size;
    memcpy(key_copy->key_data, key_ext->key_data, key_copy->key_size);

    return key_copy;
}
