#include "internal.h"

static int
__sign_response(struct nexus_nonce * auth_nonce,
                struct supernode   * supernode,
                struct volumekey   * volumekey,
                struct nexus_key   * owner_privkey,
                uint8_t           ** p_response_signature,
                size_t             * p_signature_len)
{
    uint8_t   response_hash[CONFIG_HASH_BYTES] = { 0 };
    uint8_t * response_signature               = NULL;

    mbedtls_ctr_drbg_context drbg_context;

    int ret = -1;

    // sha256(nonce | supernode | volkey)
    {
        mbedtls_sha256_context sha_context;

        mbedtls_sha256_init(&sha_context);
        mbedtls_sha256_starts(&sha_context, 0);

        mbedtls_sha256_update(
            &sha_context, (uint8_t *)auth_nonce, sizeof(struct nexus_nonce));
        mbedtls_sha256_update(
            &sha_context, (uint8_t *)supernode, supernode->header.total_size);
        mbedtls_sha256_update(
            &sha_context, (uint8_t *)volumekey, sizeof(struct volumekey));

        mbedtls_sha256_finish(&sha_context, response_hash);

        mbedtls_sha256_free(&sha_context);
    }


    mbedtls_ctr_drbg_init(&drbg_context);

    // Initialize the random number generator
    {
        mbedtls_entropy_context entropy;

        mbedtls_entropy_init(&entropy);

        // seed with the default strong source of random numbers;
        ret = mbedtls_ctr_drbg_seed(
            &drbg_context, mbedtls_entropy_func, &entropy, NULL, 0);

        if (ret != 0) {
            log_error("mbedtls_ctr_drbg_seed(ret = %#x) FAILED", ret);
            goto out;
        }

        mbedtls_entropy_free(&entropy);
    }


    // allocate the buffer for the response
    response_signature = (uint8_t *)calloc(1, MBEDTLS_MPI_MAX_SIZE);

    if (response_signature == NULL) {
        log_error("allocation error");
        return -1;
    }


    // perform the signature
    {
        mbedtls_pk_context pk;

        mbedtls_pk_init(&pk);



        ret = mbedtls_pk_parse_key(
            &pk, owner_privkey->data, owner_privkey->key_size, NULL, 0);

        if (ret != 0) {
            log_error("mbedtls_pk_parse_key(ret=%#x)", ret);
            goto out;
        }


        ret = mbedtls_pk_sign(&pk,
                              MBEDTLS_MD_SHA256,
                              response_hash,
                              0,
                              response_signature,
                              p_signature_len,
                              mbedtls_ctr_drbg_random,
                              &drbg_context);

        if (ret != 0) {
            log_error("mbedtls_pk_sign(ret=%#x)", ret);
            goto out;
        }


        mbedtls_pk_free(&pk);
    }


    *p_response_signature = response_signature;

    ret = 0;
out:
    if (ret) {
        if (response_signature) {
            nexus_free(response_signature);
        }
    }

    mbedtls_ctr_drbg_free(&drbg_context);
    return ret;
}

int
sgx_backend_open_volume(struct supernode * supernode,
                        struct volumekey * volumekey,
                        struct nexus_key * user_pubkey,
                        struct nexus_key * user_privkey)
{
    struct nexus_nonce nonce_challenge;

    uint8_t * signature     = NULL;
    size_t    signature_len = 0;

    int err = -1;
    int ret = -1;

    // call the enclave to receive a challenge
    err = ecall_authentication_request(
        global_enclave_id, &ret, user_pubkey, &nonce_challenge);

    if (err != 0 || ret != 0) {
        log_error("ecall_authentication_request() FAILED");
        goto out;
    }


    // generate a response and send to the enclave
    ret = __sign_response(&nonce_challenge,
                          supernode,
                          volumekey,
                          user_privkey,
                          &signature,
                          &signature_len);

    if (ret != 0) {
        log_error("signing response failed");
        goto out;
    }



    err = ecall_authentication_response(global_enclave_id,
                                        &ret,
                                        volumekey,
                                        supernode,
                                        signature,
                                        signature_len);

    if (err != 0 || ret != 0) {
        log_error("ecall_authentication_response() FAILED");
        goto out;
    }

    ret = 0;
out:
    if (signature) {
        nexus_free(signature);
    }

    return ret;
}

int
sgx_backend_create_volume(struct nexus_key  * owner_pubkey,
                          struct supernode ** p_supernode,
                          struct volumekey ** p_volumekey)
{
    struct supernode * supernode = NULL;
    struct volumekey * volumekey = NULL;

    struct nexus_uuid root_uuid;
    struct nexus_uuid supernode_uuid;

    int err = -1;
    int ret = -1;



    nexus_uuid_gen(&root_uuid);
    nexus_uuid_gen(&supernode_uuid);


    supernode = (struct supernode *)calloc(1, sizeof(struct supernode));
    volumekey = (struct volumekey *)calloc(1, sizeof(struct volumekey));

    if (supernode == NULL || volumekey == NULL) {
        log_error("allocation error");
        goto out;
    }


    err = ecall_create_volume(global_enclave_id,
                              &ret,
                              &supernode_uuid,
                              &root_uuid,
                              owner_pubkey,
                              supernode,
                              NULL, // root_dirnode,
                              volumekey);

    if (err || ret) {
        log_error("ecall_create_volume FAILED (err=%#x, ret=%d)", err, ret);
        goto out;
    }



    *p_supernode = supernode;
    *p_volumekey = volumekey;

    ret = 0;
out:
    if (ret) {
        if (supernode) {
            nexus_free(supernode);
        }

        if (volumekey) {
            nexus_free(volumekey);
        }
    }

    return ret;
}
