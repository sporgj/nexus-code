#include <stdlib.h>

#include <sgx_urts.h>

#include "internal.h"

#include <nexus_user_data.h>

#define DEFAULT_ENCLAVE_PATH "nexus_enclave.signed.so"

static int
init_enclave(const char * enclave_fpath, sgx_enclave_id_t * p_enclave_id)
{
    sgx_launch_token_t token = { 0 };

    int updated = 0;

    int ret = -1;

    /* initialize the enclave */
    ret = sgx_create_enclave(
        enclave_fpath, SGX_DEBUG_FLAG, &token, &updated, p_enclave_id, NULL);

    if (ret != SGX_SUCCESS) {
        log_error("Could not open enclave(%s): ret=%#x\n", enclave_fpath, ret);
        return -1;
    }

    return 0;
}

static int
exit_enclave(sgx_enclave_id_t enclave_id)
{
    int ret = 0;

    log_debug("Destroying enclave (eid=%zu)", enclave_id);

    ret = sgx_destroy_enclave(enclave_id);

    return ret;
}


static void *
sgx_backend_init(nexus_json_obj_t backend_cfg)
{
    struct sgx_backend_info * sgx_backend = NULL;

    char * enclave_path = NULL;

    int ret = -1;


    ret = nexus_json_get_string(backend_cfg, "enclave_path", &enclave_path);
    if (ret) {
        log_error("sgx_backend: no 'enclave_path' in config\n");
        return NULL;
    }


    sgx_backend = nexus_malloc(sizeof(struct sgx_backend_info));

    if (init_enclave(enclave_path, &sgx_backend->enclave_id)) {
        nexus_free(sgx_backend);

        log_error("nexus_init_enclave FAILED\n");
        return NULL;
    }

    {
        int err = -1;

        err = ecall_init_enclave(sgx_backend->enclave_id, &ret, sgx_backend);

        if (err || ret) {
            log_error("ecall_init_enclave() FAILED\n");

            exit_enclave(sgx_backend->enclave_id);

            nexus_free(sgx_backend);

            return NULL;
        }
    }

    return sgx_backend;
}

static int
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


    // assign the volumekey
    {
        struct nexus_key * vol_key = NULL;

        vol_key = nexus_alloc_generic_key(sealed_volumekey,
                                          sealed_volumekey->size);

        if (vol_key == NULL) {
            ret = -1;

            log_error("allocating generic key FAILED\n");
            goto out;
        }


        nexus_copy_key(vol_key, &volume->vol_key);
        nexus_free_key(vol_key); // deletes sealed_volumekey
    }


    ret = 0;
out:
    if (public_key_str) {
        nexus_free(public_key_str);
    }

    if (ret) {
        if (sealed_volumekey) {
            nexus_free(sealed_volumekey);
        }
    }

    return ret;
}

static struct nexus_backend_impl sgx_backend_impl = {
    .name            = "SGX",
    .init            = sgx_backend_init,
    .volume_init     = sgx_backend_create_volume
};


nexus_register_backend(sgx_backend_impl);
