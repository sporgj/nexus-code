#include "internal.h"

static int
sgx_backend_exit(struct sgx_backend * sgx_backend)
{
    if (sgx_backend->buf_manager) {
        buffer_manager_destroy(sgx_backend->buf_manager);
    }

    nexus_free(sgx_backend);

    return 0;
}

static void *
sgx_backend_init(nexus_json_obj_t backend_cfg)
{
    struct sgx_backend * sgx_backend = NULL;

    int ret = -1;


    sgx_backend = nexus_malloc(sizeof(struct sgx_backend));

    ret = nexus_json_get_string(backend_cfg, "enclave_path", &sgx_backend->enclave_path);

    if (ret != 0) {
        log_error("sgx_backend: no 'enclave_path' in config\n");
        return NULL;
    }


    // create the buffer_table
    {
        struct buffer_manager * buf_manager = buffer_manager_init();

        if (buf_manager == NULL) {
            log_error("could not create a new buf manager\n");
            goto out;
        }

        sgx_backend->buf_manager = buf_manager;
    }

    sgx_backend->volume_chunk_size = NEXUS_CHUNK_SIZE;

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
    .fs_symlink      = sgx_backend_fs_symlink,
    .fs_hardlink     = sgx_backend_fs_hardlink,
    .fs_rename       = sgx_backend_fs_rename,
    .fs_encrypt      = sgx_backend_fs_encrypt,
    .fs_decrypt      = sgx_backend_fs_decrypt
};


nexus_register_backend(sgx_backend_impl);
