#include "internal.h"

int
sgx_backend_create_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend_info * sgx_backend = NULL;

    char * public_key_str = NULL;

    struct sealed_buffer * sealed_volumekey = NULL;

    int ret = -1;


    sgx_backend = (struct sgx_backend_info *)priv_data;

    // derive the public key string
    {
        struct nexus_key  * user_prv_key = NULL;
        struct nexus_key  * user_pub_key = NULL;

        user_prv_key = nexus_get_user_key();

        if (user_prv_key == NULL) {
            log_error("Could not retrieve user key\n");
            return -1;
        }

        user_pub_key = nexus_derive_key(NEXUS_MBEDTLS_PUB_KEY, user_prv_key);

        nexus_free_key(user_prv_key);


        if (user_pub_key == NULL) {
            log_error("Could not derive user public key\n");
            goto out;
        }

        public_key_str = nexus_key_to_str(user_pub_key);

        nexus_free_key(user_pub_key);
    }


    // call the enclave
    {
        struct raw_buffer user_pubkey_rawbuf = {
            .size           = strlen(public_key_str),
            .untrusted_addr = public_key_str
        };

        sgx_backend->volume = volume;


        int err = ecall_create_volume(sgx_backend->enclave_id,
                                      &ret,
                                      &user_pubkey_rawbuf,
                                      &volume->supernode_uuid,
                                      &sealed_volumekey);

        if (err || ret) {
            log_error("ecall_create_volume() FAILED\n");
            goto out;
        }

        // restore the volume pointer
        sgx_backend->volume = NULL;
    }


#if 0
    // assign the volumekey
    {
        struct nexus_key * vol_key = NULL;

        size_t tsize = sealed_volumekey->size + sizeof(struct sealed_buffer);

        // copy the whole sealed key struct into the nexus_key object
        vol_key = nexus_key_from_binary(NEXUS_RAW_SEALED_KEY,
                                        sealed_volumekey,
                                        tsize);

        if (vol_key == NULL) {
            ret = -1;

            log_error("allocating generic key FAILED\n");
            goto out;
        }


        nexus_copy_key(vol_key, &volume->vol_key);
        nexus_free_key(vol_key);
    }
#endif

    ret = 0;
out:
    if (public_key_str) {
        nexus_free(public_key_str);
    }

    if (sealed_volumekey) {
        nexus_free(sealed_volumekey);
    }

    return ret;
}

static int
sign_response(struct nexus_key      * user_privkey,
              struct sealed_buffer  * sealed_volkey,
              struct raw_buffer     * nonce,
              struct crypto_buffer  * supernode_buffer,
              uint8_t              ** p_signature,
              size_t                * signature_len)
{
    // TODO
    return -1;
}

int
sgx_backend_open_volume(struct nexus_volume * volume, void * priv_data)
{
    struct sgx_backend_info * sgx_backend = NULL;

    struct nexus_key     * user_prv_key   = NULL;

    // request stuff
    char                 * public_key_str = NULL;
    struct raw_buffer    * nonce_rawbuf   = NULL;

    // response data
    struct crypto_buffer * supernode_cryptobuf = NULL;
    uint8_t              * signature_buf       = NULL;
    size_t                 signature_len       = 0;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend_info *)priv_data;

    // get the necessary keys
    {
        struct nexus_key * user_pub_key   = NULL;

        user_prv_key = nexus_get_user_key();
        if (user_prv_key == NULL) {
            log_error("Could not retrieve user key\n");
            goto out;
        }

        user_pub_key = nexus_derive_key(NEXUS_MBEDTLS_PUB_KEY, user_prv_key);
        if (user_pub_key == NULL) {
            log_error("Could not derive user public key\n");
            goto out;
        }

        public_key_str = nexus_key_to_str(user_pub_key);

        nexus_free_key(user_pub_key);

        if (public_key_str == NULL) {
            log_error("nexus_key_to_str for public key FAILED\n");
            goto out;
        }
    }

    // request the authentication nonce
    {
        struct raw_buffer user_pubkey_rawbuf = {
            .size           = strlen(public_key_str),
            .untrusted_addr = public_key_str
        };

        // the volume key is stored as a sealed buffer
        err = ecall_auth_request(sgx_backend->enclave_id,
                                 &ret,
                                 &user_pubkey_rawbuf,
                                 (struct sealed_buffer *)volume->vol_key->key,
                                 &nonce_rawbuf);

        if (err || ret) {
            log_error("ecall_auth_request FAILED\n");
            goto out;
        }
    }


    // read the supernode 
    supernode_cryptobuf = ocall_metadata_get(&volume->supernode_uuid,
                                             NULL,
                                             sgx_backend);

    if (supernode_cryptobuf) {
        goto out;
    }


    // generate the signature
    ret = sign_response(user_prv_key,
                        sealed_volkey,
                        nonce_rawbuf,
                        supernode_cryptobuf,
                        &signature_buf,
                        &signature_len);

    if (ret) {
        log_error("auth_response FAILED\n");
        goto out;
    }


    // send response to the enclave
    {
        struct raw_buffer signature_rawbuf = { 
            .size           = signature_len,
            .untrusted_addr = signature_buf
        };


        err = ecall_auth_response(sgx_backend->enclave_id,
                                  &ret,
                                  supernode_cryptobuf,
                                  &signature_rawbuf);

        if (err || ret) {
            log_error("ecall_auth_response() FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    if (user_prv_key) {
        nexus_free_key(user_prv_key);
    }

    if (public_key_str) {
        nexus_free(public_key_str);
    }

    if (nonce_rawbuf) {
        nexus_rawbuf_free(nonce_rawbuf);
    }

    if (signature_buf) {
        nexus_free(signature_buf);
    }

    if (supernode_cryptobuf) {
        nexus_cryptobuf_free(supernode_cryptobuf);
    }

    return ret;
}
