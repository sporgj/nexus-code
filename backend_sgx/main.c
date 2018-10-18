#include "internal.h"

#include <sys/mman.h>

#define  HEAP_SIZE      (1 << 25)

int
uuid_equal_func(uintptr_t key1, uintptr_t key2)
{
    return (nexus_uuid_compare((struct nexus_uuid *)key1, (struct nexus_uuid *)key2) == 0);
}

uint32_t
uuid_hash_func(uintptr_t key)
{
    return nexus_uuid_hash((struct nexus_uuid *)key);
}

int
nxs_create_enclave(const char * enclave_path, sgx_enclave_id_t * enclave_id)
{
    sgx_launch_token_t launch_token        = { 0 };
    int                launch_token_update = 0;

    int ret = sgx_create_enclave(enclave_path,
                                 SGX_DEBUG_FLAG,
                                 &launch_token,
                                 &launch_token_update,
                                 enclave_id,
                                 NULL);

    if (ret != SGX_SUCCESS) {
        log_error("Error, call sgx_create_enclave (%s) FAILED. ret=%x\n", enclave_path, ret);
        return -1;
    }

    return 0;
}

int
nxs_destroy_enclave(sgx_enclave_id_t enclave_id)
{
    return sgx_destroy_enclave(enclave_id);
}

static int
sgx_backend_exit(struct sgx_backend * sgx_backend)
{
    if (sgx_backend->buf_manager) {
        buffer_manager_destroy(sgx_backend->buf_manager);
    }

    if (sgx_backend->mmap_ptr) {
        munmap(sgx_backend->mmap_ptr, sgx_backend->mmap_len);
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
        goto out;
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


    // initialze the heap
    {
        sgx_backend->mmap_len = HEAP_SIZE;

        sgx_backend->mmap_ptr = mmap(0,
                                     sgx_backend->mmap_len,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS,
                                     -1,
                                     0);

        if (sgx_backend->mmap_ptr == MAP_FAILED) {
            log_error("could not mmap %zu bytes\n", sgx_backend->mmap_len);
            goto out;
        }


        nexus_heap_init(&sgx_backend->heap_manager, sgx_backend->mmap_ptr, sgx_backend->mmap_len);
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
    .fs_readdir      = sgx_backend_fs_readdir,
    .fs_symlink      = sgx_backend_fs_symlink,
    .fs_hardlink     = sgx_backend_fs_hardlink,
    .fs_rename       = sgx_backend_fs_rename,
    .fs_encrypt      = sgx_backend_fs_encrypt,
    .fs_decrypt      = sgx_backend_fs_decrypt,

    .user_list       = sgx_backend_user_list,
    .user_add        = sgx_backend_user_add,
    .user_delname    = sgx_backend_user_delname,
    .user_delkey     = sgx_backend_user_delkey,
    .user_findname   = sgx_backend_user_findname,
    .user_findkey    = sgx_backend_user_findkey
};


nexus_register_backend(sgx_backend_impl);
