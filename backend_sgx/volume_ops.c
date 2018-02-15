#include "internal.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

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
    struct sgx_backend      * sgx_backend    = NULL;

    char                    * public_key_str = NULL;

    struct nexus_key_buffer   volkey_keybuf;

    int ret = -1;


    key_buffer_init(&volkey_keybuf);

    sgx_backend = (struct sgx_backend *)priv_data;

    // derive the public key string
    public_key_str = __user_pubkey_str(NULL);
    if (public_key_str == NULL) {
        return -1;
    }

    {
        // the enclave calls ocall_metadata_set, which needs a volume pointer
        // to the backend info
        sgx_backend->volume = volume;

        int err = ecall_create_volume(sgx_backend->enclave_id,
                                      &ret,
                                      public_key_str,
                                      &volume->supernode_uuid,
                                      &volkey_keybuf);

        // restore the volume pointer
        sgx_backend->volume = NULL;

        if (err || ret) {
            log_error("ecall_create_volume() FAILED\n");
            goto out;
        }
    }

    // copy the volumekey from the buffer_manager
    {
        ret = key_buffer_derive(&volkey_keybuf, &volume->vol_key);

        key_buffer_free(&volkey_keybuf);

        if (ret != 0) {
            log_error("key_buffer_derive() FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    if (public_key_str) {
        nexus_free(public_key_str);
    }

    return ret;
}

static struct nexus_uuid *
__sign_response(struct sgx_backend      * sgx_backend,
                struct nonce_challenge  * nonce,
                struct nexus_key        * user_prv_key,
                uint8_t                 * signature_buf,
                size_t                  * signature_len)
{
    struct nexus_uuid * supernode_uuid = NULL;
    uint8_t           * supernode_buffer  = NULL;
    size_t              supernode_buflen  = 0;

    uint8_t hash[32] = { 0 };

    int ret = -1;


    /* 1 - Read the supernode from the backend */
    {
        supernode_uuid = &(sgx_backend->volume->supernode_uuid);

        ret = nexus_datastore_get_uuid(sgx_backend->volume->metadata_store,
                                       supernode_uuid,
                                       NULL,
                                       &supernode_buffer,
                                       (uint32_t *)&supernode_buflen);

        if (ret) {
            log_error("nexus_datastore_get_uuid FAILED\n");
            return NULL;
        }

        ret = buffer_manager_add(sgx_backend->buf_manager,
                                 supernode_buffer,
                                 supernode_buflen,
                                 supernode_uuid);

        if (supernode_uuid == NULL) {
            nexus_free(supernode_buffer);
            log_error("could not read the supernode\n");
            return NULL;
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

        ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
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

    ret = 0;
out:
    if (ret) {
        buffer_manager_put(sgx_backend->buf_manager, supernode_uuid);
        nexus_free(supernode_uuid);

        return NULL;
    }

    return supernode_uuid;
}

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend * sgx_backend       = NULL;

    struct nexus_key_buffer volkey_buffer;

    struct nexus_key   * user_prv_key      = NULL;
    char               * public_key_str    = NULL;

    struct nexus_uuid  * supernode_uuid = NULL;

    uint8_t signature_buffer[MBEDTLS_MPI_MAX_SIZE] = { 0 };
    size_t  signature_len                          = 0;

    struct nonce_challenge nonce;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    sgx_backend->volume = volume;

    // get the user's public key and the volume key
    public_key_str = __user_pubkey_str(&user_prv_key);
    if (public_key_str == NULL) {
        log_error("could not get user's public key\n");
        return -1;
    }

    key_buffer_init(&volkey_buffer);

    ret = key_buffer_put(&volkey_buffer, &volume->vol_key);

    if (ret != 0) {
        nexus_free(public_key_str);
        return -1;
    }

    // request a challenge from the enclave
    {
        err = ecall_authentication_challenge(sgx_backend->enclave_id,
                                             &ret,
                                             public_key_str,
                                             &volkey_buffer,
                                             &nonce);

        if (err || ret) {
            ret = -1;

            log_error("ecall_authentication_challenge FAILED\n");
            goto out;
        }
    }

    // generate the response
    {
        ret = -1;


        supernode_uuid = __sign_response(sgx_backend,
                                            &nonce,
                                            user_prv_key,
                                            signature_buffer,
                                            &signature_len);

        if (supernode_uuid == NULL) {
            log_error("could not generate response\n");
            goto out;
        }
    }

    // respond to the challenge
    {
        err = ecall_authentication_response(sgx_backend->enclave_id,
                                            &ret,
                                            supernode_uuid,
                                            signature_buffer,
                                            signature_len);

        if (err || ret) {
            ret = -1;

            log_error("ecall_authentication_response FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    nexus_free_key(user_prv_key);
    nexus_free(user_prv_key);

    nexus_free(public_key_str);

    key_buffer_free(&volkey_buffer);

    if (supernode_uuid) {
        buffer_manager_put(sgx_backend->buf_manager, supernode_uuid);
        nexus_free(supernode_uuid);
    }

    if (ret) {
        sgx_backend->volume = NULL;
    }

    return ret;
}
