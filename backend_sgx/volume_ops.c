#include "internal.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

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

static struct nexus_uuid *
__user_volkey_bufuuid(struct sgx_backend * sgx_backend)
{
    struct nexus_uuid * volkey_bufuuid = NULL;
    struct nexus_key  * sealed_volkey  = NULL;

    sealed_volkey = &(sgx_backend->volume->vol_key);

    if (sealed_volkey == NULL) {
        log_error("could not clone volumekey\n");
        return NULL;
    }

    volkey_bufuuid = buffer_manager_add_explicit(sgx_backend->buf_manager,
                                                 __vol_key_data(sealed_volkey),
                                                 __vol_key_bytes(sealed_volkey));

    if (volkey_bufuuid == NULL) {
        log_error("could not copy volkey into buffer_manager\n");
        return NULL;
    }

    return volkey_bufuuid;
}

int
sgx_backend_create_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    char * public_key_str = NULL;

    struct nexus_uuid * volkey_bufuuid = NULL;

    int ret = -1;


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

        volkey_bufuuid = nexus_malloc(sizeof(struct nexus_key));

        int err = ecall_create_volume(sgx_backend->enclave_id,
                                      &ret,
                                      public_key_str,
                                      &volume->supernode_uuid,
                                      volkey_bufuuid);

        // restore the volume pointer
        sgx_backend->volume = NULL;

        if (err || ret) {
            nexus_free(volkey_bufuuid);

            log_error("ecall_create_volume() FAILED\n");
            goto out;
        }
    }

    // copy the volumekey from the buffer_manager
    {
        uint8_t * volkey_buffer = NULL;
        size_t    volkey_buflen = 0;

        ret = -1;


        volkey_buffer  = buffer_manager_get(sgx_backend->buf_manager,
                                            volkey_bufuuid,
                                            &volkey_buflen); // refcount = 2

        if (volkey_buffer == NULL) {
            log_error("buffer_manager_get() FAILED\n");
            goto out;
        }

        buffer_manager_put(sgx_backend->buf_manager, volkey_bufuuid); // refcount = 1

        ret = __vol_key_create_key(&volume->vol_key, volkey_buffer, volkey_buflen);
        if (ret != 0) {
            log_error("__vol_key_create_key() FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    if (public_key_str) {
        nexus_free(public_key_str);
    }

    if (volkey_bufuuid) {
        buffer_manager_put(sgx_backend->buf_manager, volkey_bufuuid); // refcount = 0, deleted
        nexus_free(volkey_bufuuid);
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
    struct nexus_uuid * supernode_bufuuid = NULL;
    uint8_t           * supernode_buffer  = NULL;
    size_t              supernode_buflen  = 0;

    uint8_t hash[32] = { 0 };

    int ret = -1;


    /* 1 - Read the supernode from the backend */
    {
        ret = nexus_datastore_get_uuid(sgx_backend->volume->metadata_store,
                                       &(sgx_backend->volume->supernode_uuid),
                                       NULL,
                                       &supernode_buffer,
                                       (uint32_t *)&supernode_buflen);

        if (ret) {
            log_error("nexus_datastore_get_uuid FAILED\n");
            return NULL;
        }

        supernode_bufuuid = buffer_manager_add(sgx_backend->buf_manager,
                                               supernode_buffer,
                                               supernode_buflen);

        if (supernode_bufuuid == NULL) {
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
        buffer_manager_put(sgx_backend->buf_manager, supernode_bufuuid);
        nexus_free(supernode_bufuuid);

        return NULL;
    }

    return supernode_bufuuid;
}

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend * sgx_backend       = NULL;

    struct nexus_uuid  * volkey_bufuuid    = NULL;

    struct nexus_key   * user_prv_key      = NULL;
    char               * public_key_str    = NULL;

    struct nexus_uuid  * supernode_bufuuid = NULL;

    struct nexus_uuid  * signature_bufuuid = { 0 };
    size_t               signature_len     = 0;

    struct nonce_challenge nonce;

    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    sgx_backend->volume = volume;

    // get the user's publick key and the volume key
    public_key_str = __user_pubkey_str(&user_prv_key);
    if (public_key_str == NULL) {
        log_error("could not get user's public key\n");
        return -1;
    }

    volkey_bufuuid = __user_volkey_bufuuid(sgx_backend);
    if (volkey_bufuuid == NULL) {
        nexus_free(public_key_str);
        log_error("could not retrieve user volumekey\n");
        return -1;
    }

    // request a challenge from the enclave
    {
        int err = -1;

        err = ecall_authentication_challenge(sgx_backend->enclave_id,
                                             &ret,
                                             public_key_str,
                                             volkey_bufuuid,
                                             &nonce);

        if (err || ret) {
            ret = -1;

            log_error("ecall_authentication_challenge FAILED\n");
            goto out;
        }
    }

    // generate the response
    {
        uint8_t * signature_buffer = NULL;

        ret = -1;


        signature_bufuuid = nexus_malloc(sizeof(struct nexus_uuid));

        // allocate the signature buffer
        signature_buffer  = buffer_manager_alloc(sgx_backend->buf_manager,
                                                 MBEDTLS_MPI_MAX_SIZE,
                                                 signature_bufuuid);

        if (signature_buffer == NULL) {
            nexus_free(signature_bufuuid);
            log_error("could not allocate the signature buffer\n");
            goto out;
        }


        supernode_bufuuid = __sign_response(sgx_backend,
                                            &nonce,
                                            user_prv_key,
                                            signature_buffer,
                                            &signature_len);

        if (supernode_bufuuid == NULL) {
            log_error("could not generate response\n");
            goto out;
        }
    }

    // respond to the challenge
    {
        int err = -1;

        err = ecall_authentication_response(sgx_backend->enclave_id,
                                            &ret,
                                            supernode_bufuuid,
                                            signature_bufuuid,
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

    if (volkey_bufuuid) {
        buffer_manager_put(sgx_backend->buf_manager, volkey_bufuuid);
        nexus_free(volkey_bufuuid);
    }

    if (signature_bufuuid) {
        buffer_manager_put(sgx_backend->buf_manager, signature_bufuuid);
        nexus_free(signature_bufuuid);
    }

    if (supernode_bufuuid) {
        buffer_manager_put(sgx_backend->buf_manager, supernode_bufuuid);
        nexus_free(supernode_bufuuid);
    }

    if (ret) {
        sgx_backend->volume = NULL;
    }

    return ret;
}
