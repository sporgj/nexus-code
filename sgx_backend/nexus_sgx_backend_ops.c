#include "nexus_sgx_backend.h"

static int
login_sign_response(nonce_t *          auth_nonce,
                    struct supernode * supernode,
                    struct volumekey * volumekey,
                    const char *       privatekey,
                    size_t             privatekey_len,
                    uint8_t *          signature,
                    size_t *           p_signature_len)
{
    int                      ret                          = -1;
    uint8_t                  auth_hash[CONFIG_HASH_BYTES] = { 0 };
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_sha256_context   sha_ctx;
    mbedtls_pk_context       pk;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_pk_init(&pk);

    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        log_error("mbedtls_ctr_drbg_seed(ret = %#x) FAILED", ret);
        goto out;
    }

    // sha256(nonce | supernode | volkey)
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, (uint8_t *)auth_nonce, sizeof(nonce_t));
    mbedtls_sha256_update(
        &sha_ctx, (uint8_t *)supernode, supernode->header.total_size);
    mbedtls_sha256_update(
        &sha_ctx, (uint8_t *)volumekey, sizeof(struct volumekey));
    mbedtls_sha256_finish(&sha_ctx, auth_hash);

    // sign the hash
    ret = mbedtls_pk_parse_key(
        &pk, (uint8_t *)privatekey, privatekey_len, NULL, 0);
    if (ret != 0) {
        log_error("mbedtls_pk_parse_key(ret=%#x)", ret);
        goto out;
    }

    ret = mbedtls_pk_sign(&pk,
                          MBEDTLS_MD_SHA256,
                          auth_hash,
                          0,
                          signature,
                          p_signature_len,
                          mbedtls_ctr_drbg_random,
                          &ctr_drbg);
    if (ret != 0) {
        log_error("mbedtls_pk_sign(ret=%#x)", ret);
        goto out;
    }

out:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_sha256_free(&sha_ctx);
    mbedtls_pk_free(&pk);

    return ret;
}

int
nexus_auth_backend(struct supernode * supernode,
                   struct volumekey * volumekey,
                   const char *       publickey_fpath,
                   const char *       privatekey_fpath)
{
    int          ret                             = -1;
    uint8_t      signature[MBEDTLS_MPI_MAX_SIZE] = { 0 };
    size_t       signature_len                   = 0;
    size_t       publickey_len                   = 0;
    size_t       privatekey_len                  = 0;
    char *       publickey                       = NULL;
    char *       privatekey                      = NULL;
    nonce_t      auth_nonce                      = { 0 };

    ret = mbedtls_pk_load_file(
        publickey_fpath, (uint8_t **)&publickey, &publickey_len);

    if (ret != 0) {
        log_error("Could not load key: %s", publickey_fpath);
        return -1;
    }

    ret = mbedtls_pk_load_file(
        privatekey_fpath, (uint8_t **)&privatekey, &privatekey_len);

    if (ret != 0) {
        free(publickey);
        log_error("Could not load key: %s", privatekey_fpath);
        return -1;
    }

    // call the enclave to receive a challenge
    ecall_authentication_request(
        global_enclave_id, &ret, publickey, publickey_len, &auth_nonce);

    if (ret != 0) {
        log_error("ecall_authentication_request() FAILED");
        goto out;
    }

    // generate a response and send to the enclave
    ret = login_sign_response(&auth_nonce,
                              supernode,
                              volumekey,
                              privatekey,
                              privatekey_len,
                              signature,
                              &signature_len);
    if (ret != 0) {
        log_error("could not create signature response");
        goto out;
    }

    ecall_authentication_response(global_enclave_id,
                                  &ret,
                                  volumekey,
                                  supernode,
                                  signature,
                                  signature_len);
    if (ret != 0) {
        log_error("ecall_authentication_response() FAILED");
        goto out;
    }

    ret = 0;
out:
    free(publickey);
    free(privatekey);

    return ret;
}

int
backend_volume_create(struct uuid *      supernode_uuid,
                      struct uuid *      root_uuid,
                      const char *       publickey_fpath,
                      struct supernode * supernode_out,
                      struct dirnode *   root_dirnode_out,
                      struct volumekey * volume_out)
{
    int    ret        = -1;
    int    err        = -1;
    size_t pubkey_len = 0;
    char * pubkey_buf = NULL;

    ret = mbedtls_pk_load_file(
        publickey_fpath, (uint8_t **)&pubkey_buf, &pubkey_len);

    if (ret != 0) {
        log_error("Could not load key: %s", publickey_fpath);
        return -1;
    }

    err = ecall_create_volume(global_enclave_id,
                              &ret,
                              supernode_uuid,
                              root_uuid,
                              pubkey_buf,
                              pubkey_len,
                              supernode_out,
                              root_dirnode_out,
                              volume_out);

    free(pubkey_buf);

    if (err || ret) {
        log_error("ecall_create_volume FAILED ret=%d", ret);
        return -1;
    }

    return 0;
}


int
backend_dirnode_new(struct uuid *     dirnode_uuid,
                    struct uuid *     root_uuid,
                    struct dirnode ** p_dirnode)
{
    int              ret     = -1;
    int              err     = -1;
    struct dirnode * dirnode = NULL;

    dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode *));
    if (dirnode == NULL) {
        log_error("allocation error");
        return -1;
    }

    err = ecall_dirnode_new(
        global_enclave_id, &ret, dirnode_uuid, root_uuid, dirnode);

    if (err || ret) {
        free(dirnode);
        log_error("ecall_dirnode_new() FAILED");
        return -1;
    }

    *p_dirnode = dirnode;

    return 0;
}

int
backend_dirnode_add(struct dirnode *    parent_dirnode,
                    struct uuid *       uuid,
                    const char *        fname,
                    nexus_fs_obj_type_t type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_add(
        global_enclave_id, &ret, parent_dirnode, uuid, fname, type);

    if (err || ret) {
        log_error("ecall_dirnode_add FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_find_by_uuid(struct dirnode *      dirnode,
                             struct uuid *         uuid,
                             char **               p_fname,
                             nexus_fs_obj_type_t * p_type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_find_by_uuid(
        global_enclave_id, &ret, dirnode, uuid, p_fname, p_type);

    if (err || ret) {
        log_error(
            "ecall_dirnode_find_by_uuid FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_find_by_name(struct dirnode *      dirnode,
                             char *                fname,
                             struct uuid *         uuid,
                             nexus_fs_obj_type_t * p_type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_find_by_name(
        global_enclave_id, &ret, dirnode, fname, uuid, p_type);

    if (err || ret) {
        log_error(
            "ecall_dirnode_find_by_name FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_remove(struct dirnode *      dirnode,
                       char *                fname,
                       struct uuid *         uuid,
                       nexus_fs_obj_type_t * p_type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_remove(
        global_enclave_id, &ret, dirnode, fname, uuid, p_type);

    if (err || ret) {
        log_error("ecall_dirnode_remove FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_serialize(struct dirnode *  dirnode,
                          struct dirnode ** p_sealed_dirnode)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_serialize(
        global_enclave_id, &ret, dirnode, p_sealed_dirnode);

    if (err || ret) {
        log_error("ecall_dirnode_serialize FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}
