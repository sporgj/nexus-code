/**
 * File contains functions that manage Nexus volumes
 *
 * @author Judicael Djoko <jdb@djoko.me>
 */
#include <sys/stat.h>

#include "nexus_untrusted.h"

sgx_enclave_id_t global_enclave_id = 0;

void
ocall_print(const char * str)
{
    printf("%s", str);
    fflush(stdout);
}

static char *
fread_public_or_private_key(const char * key_fpath, size_t * p_klen)
{
    int    ret = -1;
    char * buf = NULL;

    ret = mbedtls_pk_load_file(key_fpath, (uint8_t **)&buf, p_klen);
    if (ret) {
        log_error("Could not load key: %s", key_fpath);
        return NULL;
    }

    return buf;
}

int
nexus_init_enclave(const char * enclave_fpath)
{
    int ret     = -1;
    int updated = 0;
    int err     = 0;

    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(enclave_fpath,
                             SGX_DEBUG_FLAG,
                             &token,
                             &updated,
                             &global_enclave_id,
                             NULL);
    if (ret != SGX_SUCCESS) {
        log_error("Could not open enclave: ret=%#x", ret);
        return -1;
    }

    ecall_init_enclave(global_enclave_id, &err);
    if (err != 0) {
        log_error("Initializing enclave failed");
        return -1;
    }

    return 0;
}

int
nexus_create_volume(char *               publickey_fpath,
                    struct supernode **  p_supernode,
                    struct dirnode **    p_root_dirnode,
                    struct volumekey ** p_sealed_volumekey)
{
    int                 ret          = -1;
    size_t              pubkey_len   = 0;
    char *              pubkey_buf   = NULL;
    struct supernode *  supernode    = NULL;
    struct dirnode *    root_dirnode = NULL;
    struct volumekey * volkey       = NULL;
    struct uuid         supernode_uuid;
    struct uuid         root_uuid;

    pubkey_buf = fread_public_or_private_key(publickey_fpath, &pubkey_len);
    if (pubkey_buf == NULL) {
        log_error("could not read public key file");
        return -1;
    }

    /* 2 -- allocate our structs and call the enclave */
    supernode    = (struct supernode *)calloc(1, sizeof(struct supernode));
    root_dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    volkey       = (struct volumekey *)calloc(1, sizeof(struct volumekey));
    if (supernode == NULL || root_dirnode == NULL || volkey == NULL) {
        log_error("allocation error");
        goto out;
    }

    nexus_uuid(&supernode_uuid);
    nexus_uuid(&root_uuid);

    ecall_create_volume(global_enclave_id,
                        &ret,
                        &supernode_uuid,
                        &root_uuid,
                        pubkey_buf,
                        pubkey_len,
                        supernode,
                        root_dirnode,
                        volkey);

    if (ret != 0) {
        log_error("ecall_create_volume FAILED ret=%d", ret);
        goto out;
    }

    *p_supernode         = supernode;
    *p_root_dirnode      = root_dirnode;
    *p_sealed_volumekey = volkey;

    ret = 0;
out:
    nexus_free(pubkey_buf);

    if (ret) {
        nexus_free2(supernode);
        nexus_free2(root_dirnode);
        nexus_free2(volkey);
    }

    return ret;
}

static int
login_sign_response(nonce_t *           auth_nonce,
                    struct supernode *  supernode,
                    struct volumekey * volumekey,
                    char *              privatekey,
                    size_t              privatekey_len,
                    uint8_t *           signature,
                    size_t *            p_signature_len)
{
    int                      ret                             = -1;
    uint8_t                  auth_hash[CONFIG_HASH_BYTES]    = { 0 };
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
nexus_login_volume(const char *        publickey_fpath,
                   const char *        privatekey_fpath,
                   struct supernode *  supernode,
                   struct volumekey * volumekey)
{
    int     ret                             = -1;
    char *  publickey                       = NULL;
    char *  privatekey                      = NULL;
    uint8_t signature[MBEDTLS_MPI_MAX_SIZE] = { 0 };
    size_t  publickey_len                   = 0;
    size_t  privatekey_len                  = 0;
    size_t  signature_len                   = 0;
    nonce_t auth_nonce                      = { 0 };

    // read the public keypair
    publickey = fread_public_or_private_key(publickey_fpath, &publickey_len);
    if (publickey == NULL) {
        log_error("reading public key: '%s' FAILED", publickey_fpath);
        goto out;
    }

    privatekey = fread_public_or_private_key(privatekey_fpath, &privatekey_len);
    if (privatekey == NULL) {
        log_error("reading private key: '%s' FAILED", privatekey_fpath);
        goto out;
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
    if (ret != 0 ) {
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
    nexus_free2(publickey);
    nexus_free2(privatekey);

    return ret;
}

int
nexus_mount_volume(const char * supernode_fpath)
{
    /* 1 -- if not logged in, exit */

    /* 2 -- Read the supernode */

    /* 3 -- Call the enclave */

    return 0;
}
