#include "internal.h"

#include <nexus_raw_file.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>


static int
load_or_create_instance(struct sgx_backend * backend)
{
    struct stat st;

    if (stat(nexus_config.instance_path, &st)) {
        nexus_printf("Instance file (%s) not found... Creating\n", nexus_config.instance_path);

        if (nxs_create_instance(backend->enclave_path, nexus_config.instance_path)) {
            log_error("could not create instance in\n");
            return -1;
        }
    }

    nexus_printf("Loading instance: %s\n", nexus_config.instance_path);

    return nxs_load_instance(nexus_config.instance_path, backend->enclave_id);
}

/* creates a new enclave */
static int
init_enclave(struct sgx_backend * backend)
{
    int err = -1;
    int ret = -1;

    if (backend->enclave_id == 0) {
        ret = main_create_enclave(backend->enclave_path, &backend->enclave_id);

        if (ret != 0) {
            log_error("Could not open enclave(%s): ret=%#x\n", backend->enclave_path, ret);
            return -1;
        }
    }

    err = ecall_init_enclave(backend->enclave_id,
                             &ret,
                             backend->volume,
                             &backend->heap_manager,
                             backend->tick_tok);

    if (err || ret) {
        log_error("ecall_init_enclave() FAILED\n");
        return -1;
    }

    return 0;
}

static int
exit_enclave(struct sgx_backend * backend)
{
    int ret = 0;

    log_debug("Destroying enclave (eid=%zu)", backend->enclave_id);

    ret = sgx_destroy_enclave(backend->enclave_id);

    backend->enclave_id = 0;

    return ret;
}

// TODO refactor this
//
static char *
__user_pubkey_str(struct nexus_key ** optional_privkey)
{
    char * public_key_str = NULL;

    struct nexus_key  * user_prv_key = NULL;
    struct nexus_key  * user_pub_key = NULL;


    user_prv_key = nexus_get_user_key();

    if (user_prv_key == NULL) {
        log_error("Could not retrieve user key\n");
        return NULL;
    }

    user_pub_key = nexus_derive_key(NEXUS_MBEDTLS_PUB_KEY, user_prv_key);

    if (user_pub_key == NULL) {
        nexus_free_key(user_prv_key);
        nexus_free(user_prv_key);

        log_error("Could not derive user public key\n");
        return NULL;
    }

    public_key_str = nexus_key_to_str(user_pub_key);

    nexus_free_key(user_pub_key);
    nexus_free(user_pub_key);

    if (optional_privkey != NULL) {
        *optional_privkey = user_prv_key;
    } else {
        nexus_free_key(user_prv_key);
        nexus_free(user_prv_key);
    }

    return public_key_str;
}

int
sgx_backend_create_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend      * sgx_backend    = (struct sgx_backend *)priv_data;

    char                    * public_key_str = NULL;

    struct nexus_key_buffer   volkey_keybuf;

    int ret = -1;


    // derive the public key string
    public_key_str = __user_pubkey_str(NULL);

    if (public_key_str == NULL) {
        return -1;
    }


    sgx_backend->volume = volume;

    if (init_enclave(sgx_backend)) {
        nexus_free(public_key_str);

        log_error("could not initialize the enclave\n");
        return -1;
    }


    if (global_nxs_instance == NULL && load_or_create_instance(sgx_backend)) {
        log_error("backend instance needs to be initialized\n");
        return -1;
    }


    key_buffer_init(&volkey_keybuf);

    {
        // for the ocalls
        volume->private_data = sgx_backend;

        int err = ecall_create_volume(sgx_backend->enclave_id,
                                      &ret,
                                      public_key_str,
                                      &volume->supernode_uuid,
                                      &volkey_keybuf);

        volume->private_data = NULL;

        if (err || ret) {
            log_error("ecall_create_volume() FAILED\n");
            goto out;
        }
    }


    ret = key_buffer_derive(&volkey_keybuf, &volume->vol_key);

    if (ret != 0) {
        log_error("key_buffer_derive() FAILED\n");
        goto out;
    }

    ret = 0;
out:
    nexus_free(public_key_str);

    key_buffer_free(&volkey_keybuf);

    exit_enclave(sgx_backend);

    sgx_backend->volume = NULL;

    return ret;
}

static int
__sign_response(struct sgx_backend      * sgx_backend,
                struct nonce_challenge  * nonce,
                struct nexus_key        * user_prv_key,
                uint8_t                 * signature_buf,
                size_t                  * signature_len)
{
    uint8_t           * supernode_buffer = NULL;
    size_t              supernode_buflen = 0;

    uint8_t hash[32] = { 0 };

    int ret = -1;


    /* 1 - Read the supernode from the backend */
    {
        size_t timestamp = 0;

        supernode_buffer = io_buffer_get(&(sgx_backend->volume->supernode_uuid),
                                         NEXUS_FREAD,
                                         &supernode_buflen,
                                         &timestamp,
                                         sgx_backend->volume);

        if (supernode_buffer == NULL) {
            log_error("io_buffer_get FAILED\n");
            return -1;
        }
    }

    /* 2 - hash the contents */
    {
        mbedtls_sha256_context sha_context;

        mbedtls_sha256_init(&sha_context);

        // sha256(nonce | volkey | supernode)
        mbedtls_sha256_starts(&sha_context, 0);

        mbedtls_sha256_update(&sha_context, nonce->bytes, sizeof(struct nonce_challenge));
        mbedtls_sha256_update(&sha_context, supernode_buffer, supernode_buflen);

        mbedtls_sha256_finish(&sha_context, hash);

        mbedtls_sha256_free(&sha_context);
    }

    /* 3 - Generate the signature */
    {
        mbedtls_entropy_context  entropy;
        mbedtls_ctr_drbg_context ctr_drbg;

        mbedtls_pk_context * pk_context = NULL;


        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
        if (ret != 0) {
            log_error("mbedtls_ctr_drbg_seed FAILED (ret=-0x%04x)\n", ret);
            goto out;
        }

        // nexus_key already initializes the private key context
        pk_context = (mbedtls_pk_context *) user_prv_key->key;

        ret = mbedtls_pk_sign(pk_context,
                              MBEDTLS_MD_SHA256,
                              hash,
                              0,
                              signature_buf,
                              signature_len,
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg);

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        if (ret != 0) {
            log_error("mbedtls_pk_sign FAILED (ret=-0x%04x)\n", ret);
            goto out;
        }
    }

    return 0;
out:

    return -1;
}

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend * sgx_backend       = (struct sgx_backend *)priv_data;

    struct nexus_key   * user_prv_key      = NULL;
    char               * public_key_str    = NULL;

    struct nonce_challenge nonce;

    int err = -1;
    int ret = -1;


    // get the user's public key and the volume key
    public_key_str = __user_pubkey_str(&user_prv_key);

    if (public_key_str == NULL) {
        log_error("could not get user's public key\n");
        return -1;
    }


    sgx_backend->volume = volume;

    if (init_enclave(sgx_backend)) {
        nexus_free(public_key_str);

        sgx_backend->volume = NULL;

        log_error("could not initialize the enclave\n");
        return -1;
    }

    if (global_nxs_instance == NULL && load_or_create_instance(sgx_backend)) {
        log_error("backend instance needs to be initialized\n");
        return -1;
    }


    volume->private_data = sgx_backend;

    // request a challenge from the enclave
    {
        struct nexus_key_buffer volkey_buffer;

        key_buffer_init(&volkey_buffer);

        ret = key_buffer_put(&volkey_buffer, &volume->vol_key);

        if (ret != 0) {
            nexus_free(public_key_str);

            log_error("could not write volumekey into key buffer\n");
            goto out;
        }

        err = ecall_authentication_challenge(sgx_backend->enclave_id,
                                             &ret,
                                             public_key_str,
                                             &volkey_buffer,
                                             &nonce);

        key_buffer_free(&volkey_buffer);

        if (err || ret) {
            ret = -1;

            log_error("ecall_authentication_challenge FAILED\n");
            goto out;
        }
    }

    // respond to the challenge
    {
        uint8_t signature_buffer[MBEDTLS_MPI_MAX_SIZE] = { 0 };
        size_t  signature_len                          = 0;

        ret = __sign_response(sgx_backend, &nonce, user_prv_key, signature_buffer, &signature_len);

        if (ret != 0) {
            log_error("could not generate response\n");
            goto out;
        }


        err = ecall_authentication_response(sgx_backend->enclave_id,
                                            &ret,
                                            &(volume->supernode_uuid),
                                            signature_buffer,
                                            signature_len);

        if (err || ret) {
            ret = -1;

            log_error("ecall_authentication_response FAILED\n");
            goto out;
        }
    }

    sgx_backend->volume = volume;

    ret = 0;
out:
    nexus_free_key(user_prv_key);
    nexus_free(user_prv_key);

    nexus_free(public_key_str);

    if (ret) {
        exit_enclave(sgx_backend);

        sgx_backend->volume  = NULL;

        volume->private_data = NULL;
    }

    return ret;
}
