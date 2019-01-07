#include "../enclave_internal.h"

static int
__nxs_chunk_crypto(struct nexus_filenode * filenode,
                   uint8_t               * input_buffer_in,
                   uint8_t               * output_buffer_in,
                   size_t                  offset,
                   size_t                  size,
                   size_t                  filesize,
                   nexus_crypto_mode_t     mode)
{
    struct nexus_data_buf * data_buffer  = NULL;

    struct nexus_crypto_ctx * crypto_ctx = NULL;

    int ret = -1;


    crypto_ctx = filenode_get_chunk(filenode, offset);

    if (crypto_ctx == NULL) {
        log_error("filenode_get_chunk(offset=%zu)\n", offset);
        return -1;
    }

    if (mode == NEXUS_ENCRYPT) {
        nexus_crypto_ctx_generate(crypto_ctx);
    }


    data_buffer = nexus_data_buf_new(crypto_ctx, global_chunk_size, mode);

    if (data_buffer == NULL) {
        log_error("could not create a new data_buffer\n");
        return -1;
    }


    ret = nexus_data_buf_write(data_buffer, input_buffer_in, output_buffer_in, size);

    if (ret != 0) {
        log_error("could not write data_buffer\n");
        goto out;
    }

    // store the generated mac
    if (mode == NEXUS_ENCRYPT) {
        nexus_data_buf_flush(data_buffer, &crypto_ctx->mac);
    } else {
        // DECRYPT
        struct nexus_mac computed_mac;

        nexus_data_buf_flush(data_buffer, &computed_mac);

        if (nexus_mac_compare(&crypto_ctx->mac, &computed_mac)) {
            ret = -1;
            log_error("mac comparison FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    nexus_data_buf_free(data_buffer);

    return ret;
}

int
__nxs_fs_crypto(char              * filepath_IN,
                uint8_t           * input_buffer_in,
                uint8_t           * output_buffer_in,
                size_t              offset,
                size_t              size,
                size_t              filesize,
                nexus_crypto_mode_t mode)
{
    struct nexus_metadata * metadata = NULL;

    nexus_io_flags_t io_mode = (mode == NEXUS_ENCRYPT) ? NEXUS_FRDWR : NEXUS_FREAD;

    int ret = -1;


    metadata = nexus_vfs_get(filepath_IN, io_mode);

    if (metadata == NULL) {
        log_error("could not get metadata (%s)\n", filepath_IN);
        return -1;
    }

    if (mode == NEXUS_ENCRYPT) {
        ret = filenode_set_filesize(metadata->filenode, filesize);

        if (ret != 0) {
            log_error("filenode_set_filesize(%zu) FAILED\n", filesize);
            goto out;
        }
    }

    ret = __nxs_chunk_crypto(metadata->filenode,
                             input_buffer_in,
                             output_buffer_in,
                             offset,
                             size,
                             filesize,
                             mode);

    if (ret != 0) {
        log_error("chunk processing failed\n");
        goto out;
    }


    ret = nexus_metadata_store(metadata);

    if (ret != 0) {
        log_error("nexus_metadata_store FAILED\n");
        goto out;
    }

    ret = 0;
out:
    nexus_vfs_put(metadata);

    return ret;
}


int
ecall_fs_encrypt(char    * filepath_IN,
                 uint8_t * input_buffer_in,
                 uint8_t * output_buffer_in,
                 size_t    offset,
                 size_t    size,
                 size_t    filesize)
{
    int ret = -1;

    sgx_spin_lock(&vfs_ops_lock);

    ret  = __nxs_fs_crypto(filepath_IN,
                           input_buffer_in,
                           output_buffer_in,
                           offset,
                           size,
                           filesize,
                           NEXUS_ENCRYPT);

    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}

int
ecall_fs_decrypt(char    * filepath_IN,
                 uint8_t * input_buffer_in,
                 uint8_t * output_buffer_in,
                 size_t    offset,
                 size_t    size,
                 size_t    filesize)
{
    int ret = -1;

    sgx_spin_lock(&vfs_ops_lock);

    ret  = __nxs_fs_crypto(filepath_IN,
                           input_buffer_in,
                           output_buffer_in,
                           offset,
                           size,
                           filesize,
                           NEXUS_DECRYPT);

    sgx_spin_unlock(&vfs_ops_lock);

    return ret;
}

int
ecall_fs_truncate(char * filepath_IN, size_t size, struct nexus_stat * stat_out)
{
    struct nexus_metadata * metadata = NULL;
    struct nexus_filenode * filenode = NULL;


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(filepath_IN, NEXUS_FRDWR);

    if (metadata == NULL) {
        log_error("could not get metadata (%s)\n", filepath_IN);
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }


    filenode = metadata->filenode;

    // TODO check access control
    filenode_set_filesize(filenode, size);

    if (nexus_metadata_store(metadata)) {
        nexus_vfs_put(metadata);
        log_error("nexus_metadata_store FAILED\n");
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    filenode_export_stat(metadata->filenode, stat_out);

    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);

    return 0;
}
