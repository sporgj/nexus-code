#include "internal.h"

struct nxs_instance * global_nxs_instance = NULL;

int
nxs_create_instance(char * enclave_path, char * instance_fpath)
{
    struct nxs_instance * instance = NULL;

    sgx_enclave_id_t enclave_id;


    if (nxs_create_enclave(enclave_path, &enclave_id)) {
        log_error("could not create the enclave (%s)\n", ENCLAVE_PATH);
        return -1;
    }


    instance = create_nxs_instance(enclave_id);

    if (instance == NULL) {
        log_error("could not create instance\n");
        goto err;
    }

    if (store_init_message(instance_fpath, instance)) {
        log_error("could not serialize key file\n");
        goto err;
    }

    nxs_destroy_enclave(enclave_id);

    free_init_message(instance);

    return 0;

err:
    nxs_destroy_enclave(enclave_id);

    free_init_message(instance);

    return -1;
}

int
nxs_load_instance(char * instance_fpath)
{
    struct nxs_instance * new_instance = fetch_init_message(instance_fpath);

    if (new_instance == NULL) {
        log_error("could not load: %s\n", instance_fpath);
        goto err;
    }

    if (global_nxs_instance) {
        free_init_message(global_nxs_instance);
    }

    global_nxs_instance = new_instance;

    return 0;
err:
    free_init_message(new_instance);

    return -1;
}

#if 0

int
exchange(char * other_fpath, char * secret_fpath)
{
    struct nxs_instance * other_instance = NULL;


    if (global_nxs_instance == NULL) {
        log_error("no instance mounted\n");
        return -1;
    }

    other_instance = fetch_init_message(other_fpath);

    if (other_instance == NULL) {
        log_error("could not load: %s\n", other_fpath);
        goto err;
    }

    if (validate_quote(other_instance->quote, other_instance->quote_size)) {
        log_error("validate_quote() FAILED\n");
        goto err;
    }


    // generate the exchange message and write it
    {
        struct rk_exchange * xchg_message =  NULL;

        int ret = -1;


        xchg_message = create_rk_exchange(other_instance, secret, secret_len);

        if (xchg_message == NULL) {
            log_error("create_rk_exchange FAILED\n");
            goto err;
        }


        ret = store_xchg_message(secret_fpath, xchg_message);

        free_xchg_message(xchg_message);

        if (ret) {
            log_error("could not store xchg message: %s", secret_fpath);
            goto err;
        }
    }


    free_init_message(other_instance);

    return 0;

err:
    if (other_instance) {
        free_init_message(other_instance);
    }

    return -1;
}


uint8_t *
nexus_backend_sgx_extract_rootkey(char * secret_fpath, int * sealed_rootkey_len)
{
    uint8_t            * sealed_rootkey_buf = NULL;

    struct rk_exchange * xchg_message       = NULL;


    if (global_nxs_instance == NULL) {
        log_error("no instance mounted\n");
        return -1;
    }


    xchg_message = fetch_xchg_message(secret_fpath);

    if (xchg_message == NULL) {
        log_error("could not read xchg secret\n");
        goto err;
    }


    sealed_rootkey_buf = extract_rk_secret(xchg_message, sealed_rootkey_len);

    if (sealed_rootkey_buf == NULL) {
        log_error("could not extract the sealed rootkey\n");
        goto err;
    }

    // TODO add it to volume

    free_xchg_message(xchg_message);

    return sealed_rootkey_buf;

err:
    if (xchg_message) {
        free_xchg_message(xchg_message);
    }

    return NULL;
}

#endif
