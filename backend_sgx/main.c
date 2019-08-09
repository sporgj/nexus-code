#include "internal.h"

#include <sys/mman.h>

#define  HEAP_SIZE      (1 << 25)


int
main_create_enclave(const char * enclave_path, sgx_enclave_id_t * enclave_id)
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


static int
sgx_backend_exit(struct sgx_backend * sgx_backend)
{
    if (sgx_backend->buf_manager) {
        buffer_manager_destroy(sgx_backend->buf_manager);
    }

    if (sgx_backend->mmap_ptr) {
        munmap(sgx_backend->mmap_ptr, sgx_backend->mmap_len);
    }

    if (sgx_backend->enclave_path) {
        nexus_free(sgx_backend->enclave_path);
    }

    if (sgx_backend->batch_dirpath) {
        nexus_free(sgx_backend->batch_dirpath);
    }

    nexus_list_destroy(&sgx_backend->batch_deleted_uuids);

    // TODO delete the batch datastore's contents

    nexus_free(sgx_backend);

    return 0;
}


static int
initialize_batch_datastore(struct sgx_backend * backend)
{
    // TODO find better way of generating batching path
    backend->batch_dirpath = strndup("/tmp/batch-nexus", PATH_MAX);

    nexus_printf("batch_datastore init:: %s\n", backend->batch_dirpath);

    nexus_json_obj_t config_json = nexus_json_new_obj("data_store");

    if (config_json == NEXUS_JSON_INVALID_OBJ) {
        log_error("nexus_json_new_obj() FAILED\n");
        return -1;
    }

    if (nexus_json_add_string(config_json, "name", "TWOLEVEL")) {
        log_error("nexus_json_set_string FAILED\n");
        goto out_err;
    }

    if (nexus_json_add_string(config_json, "root_path", backend->batch_dirpath)) {
        log_error("nexus_json_set_string FAILED\n");
        goto out_err;
    }

    backend->batch_datastore = nexus_datastore_create("TWOLEVEL", config_json);
    if (backend->batch_datastore == NULL) {
        log_error("nexus_datastore_create() FAILED\n");
        goto out_err;
    }

    nexus_json_free(config_json);

    return 0;

out_err:
    nexus_json_free(config_json);

    return -1;
}

static void
nexus_uuid_deallocator(void * element)
{
    nexus_free(element);
}

/**
 * Initializes the backend runtime
 */
static void *
sgx_backend_init(nexus_json_obj_t backend_cfg)
{
    struct sgx_backend * sgx_backend = nexus_malloc(sizeof(struct sgx_backend));

    nexus_list_init(&sgx_backend->batch_deleted_uuids);
    nexus_list_set_deallocator(&sgx_backend->batch_deleted_uuids, nexus_uuid_deallocator);

    if (nexus_json_get_string(backend_cfg, "enclave_path", &sgx_backend->enclave_path)) {
        if (nexus_config.enclave_path) {
            log_debug("Using nexus_config.enclave_path = %s\n", nexus_config.enclave_path);
            sgx_backend->enclave_path = strndup(nexus_config.enclave_path, NEXUS_PATH_MAX);
        } else {
            log_error("sgx_backend: no 'enclave_path' in config\n");
            goto out_err;
        }
    }

    {
        char * fsync_mode_str = NULL;

        if (nexus_json_get_string(backend_cfg, "fsync_mode", &fsync_mode_str) == 0) {
            if (strncmp("1", fsync_mode_str, 1) == 0) {
                sgx_backend->fsync_mode = true;
            }
        }

        nexus_printf("backend_sgx: fsync_mode=%s\n", (sgx_backend->fsync_mode ? "TRUE" : "FALSE"));
    }

    if (initialize_batch_datastore(sgx_backend)) {
        log_error("initialize_local_datastore() FAILED\n");
        goto out_err;
    }

    // create the buffer_table
    {
        struct buffer_manager * buf_manager = buffer_manager_init();

        if (buf_manager == NULL) {
            log_error("could not create a new buf manager\n");
            goto out_err;
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
            goto out_err;
        }

        nexus_heap_init(&sgx_backend->heap_manager, sgx_backend->mmap_ptr, sgx_backend->mmap_len);
    }

    sgx_backend->tick_tok = time_ticker_create();

    sgx_backend->volume_chunk_size = NEXUS_CHUNK_SIZE;

    return sgx_backend;
out_err:
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
    .fs_create       = sgx_backend_fs_create,
    .fs_remove       = sgx_backend_fs_remove,
    .fs_lookup       = sgx_backend_fs_lookup,
    .fs_stat         = sgx_backend_fs_stat,
    .fs_readdir      = sgx_backend_fs_readdir,
    .fs_symlink      = sgx_backend_fs_symlink,
    .fs_readlink     = sgx_backend_fs_readlink,
    .fs_hardlink     = sgx_backend_fs_hardlink,
    .fs_rename       = sgx_backend_fs_rename,

    .fs_truncate     = sgx_backend_fs_truncate,

    .fs_file_encrypt_start = sgx_backend_fs_file_encrypt_start,
    .fs_file_decrypt_start = sgx_backend_fs_file_decrypt_start,
    .fs_file_crypto_seek   = sgx_backend_fs_file_crypto_seek,
    .fs_file_crypto_decrypt = sgx_backend_fs_file_crypto_decrypt,
    .fs_file_crypto_encrypt = sgx_backend_fs_file_crypto_encrypt,
    .fs_file_crypto_finish = sgx_backend_fs_file_crypto_finish,

    .user_list       = sgx_backend_user_list,
    .user_add        = sgx_backend_user_add,
    .user_delname    = sgx_backend_user_delname,
    .user_delkey     = sgx_backend_user_delkey,
    .user_findname   = sgx_backend_user_findname,
    .user_findkey    = sgx_backend_user_findkey
};


nexus_register_backend(sgx_backend_impl);


// batch mode stuff

int
sgx_backend_batch_mode_start(struct nexus_volume * volume)
{
    struct sgx_backend * backend = volume->private_data;

    pthread_mutex_lock(&backend->batch_mutex);

    if (backend->batch_mode == true) {
        pthread_mutex_unlock(&backend->batch_mutex);
        return 0;
    }

    backend->batch_mode = true;
    backend->batch_start_time = time(NULL);
    pthread_mutex_unlock(&backend->batch_mutex);

    return 0;
}

int
sgx_backend_batch_mode_commit(struct nexus_volume * volume)
{
    struct sgx_backend * backend = volume->private_data;

    int ret = -1;

    pthread_mutex_lock(&backend->batch_mutex);

    if (backend->batch_mode == false) {
        pthread_mutex_unlock(&backend->batch_mutex);
        return 0;
    }

    ret = io_buffer_sync_buffers(backend);
    if (ret) {
        log_error("io_buffer_sync_buffers() FAILED\n");
    }

    pthread_mutex_unlock(&backend->batch_mutex);

    return ret;
}

int
sgx_backend_batch_mode_finish(struct nexus_volume * volume)
{
    struct sgx_backend * backend = volume->private_data;

    pthread_mutex_lock(&backend->batch_mutex);

    if (backend->batch_mode == false) {
        pthread_mutex_unlock(&backend->batch_mutex);
        return 0;
    }

    if (io_buffer_sync_buffers(backend)) {
        log_error("io_buffer_sync_buffers() FAILED\n");
        pthread_mutex_unlock(&backend->batch_mutex);
        return -1;
    }

    backend->batch_mode = false;
    backend->batch_finish_time = time(NULL);

    pthread_mutex_unlock(&backend->batch_mutex);

    return 0;
}


int
sgx_backend_stat_uuid(struct nexus_volume  * volume,
                      struct nexus_uuid    * uuid,
                      struct nexus_fs_attr * attrs)
{
    // TODO check that the volume's backend is actually SGX
    return io_backend_stat_uuid(volume, uuid, attrs);
}

struct nexus_datastore *
sgx_backend_get_datastore(struct nexus_volume * volume, struct nexus_uuid * uuid)
{
    return io_backend_get_datastore(volume, uuid, NULL);
}
