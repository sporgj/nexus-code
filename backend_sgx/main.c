#include "internal.h"


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

static int
sgx_backend_exit(struct sgx_backend * sgx_backend)
{
    if (sgx_backend->enclave_id) {
        exit_enclave(sgx_backend->enclave_id);
    }

    if (sgx_backend->buf_manager) {
        free_buffer_manager(sgx_backend->buf_manager);
    }

    nexus_free(sgx_backend);

    return 0;
}

static void *
sgx_backend_init(nexus_json_obj_t backend_cfg)
{
    struct sgx_backend * sgx_backend = NULL;

    char * enclave_path = NULL;

    int ret = -1;


    ret = nexus_json_get_string(backend_cfg, "enclave_path", &enclave_path);
    if (ret) {
        log_error("sgx_backend: no 'enclave_path' in config\n");
        return NULL;
    }


    sgx_backend = nexus_malloc(sizeof(struct sgx_backend));

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
            goto out;
        }
    }

    // create the buffer_table
    {
        struct buffer_manager * buf_manager = new_buffer_manager();

        if (buf_manager == NULL) {
            log_error("could not create a new buf manager\n");
            goto out;
        }

        sgx_backend->buf_manager = buf_manager;
    }

    return sgx_backend;
out:
    if (sgx_backend) {
        sgx_backend_exit(sgx_backend);
    }

    return NULL;
}


static struct nexus_backend_impl sgx_backend_impl = {
    .name            = "SGX",
    .init            = sgx_backend_init,
    .deinit          = sgx_backend_exit,
    .volume_init     = sgx_backend_create_volume,
    .volume_open     = sgx_backend_open_volume,
    .fs_touch        = sgx_backend_fs_create,
    .fs_remove       = sgx_backend_fs_remove,
    .fs_lookup       = sgx_backend_fs_lookup,
    .fs_filldir      = sgx_backend_fs_filldir,
    .fs_symlink      = sgx_backend_fs_symlink
};


nexus_register_backend(sgx_backend_impl);
