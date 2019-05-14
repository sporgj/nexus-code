#include "../enclave_internal.h"

int
ecall_fs_truncate(char * filepath_IN, size_t size, struct nexus_stat * stat_out)
{
    struct nexus_metadata * metadata = NULL;


    sgx_spin_lock(&vfs_ops_lock);

    metadata = nexus_vfs_get(filepath_IN, NEXUS_FRDWR | NEXUS_IO_FCRYPTO | NEXUS_IO_FNODE);

    if (metadata == NULL) {
        log_error("could not get metadata (%s)\n", filepath_IN);
        sgx_spin_unlock(&vfs_ops_lock);
        return -1;
    }

    // ACCESS CONTROL
    if (!bouncer_access_check(metadata, PERM_WRITE)) {
        log_error("ACCESS DENIED\n");
        nexus_vfs_put(metadata);
    }

    // TODO check access control
    filenode_set_filesize(metadata->filenode, size);

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



int
__nxs_file_crypto_start(char              * filepath_IN,
                        size_t              filesize,
                        nexus_crypto_mode_t crypto_mode,
                        int               * xfer_id_out,
                        struct nexus_uuid * uuid_out,
                        size_t            * filesize_out_opt)
{
    struct nexus_metadata * metadata = NULL;

    nexus_io_flags_t io_mode = (crypto_mode == NEXUS_ENCRYPT) ? NEXUS_FRDWR : NEXUS_FREAD;

    perm_type_t permission = (io_mode == NEXUS_FREAD ? PERM_READ : PERM_WRITE);

    int xfer_id = -1;


    sgx_spin_lock(&vfs_ops_lock);

    io_mode |= NEXUS_IO_FCRYPTO;
    metadata = nexus_vfs_get(filepath_IN, io_mode);

    if (metadata == NULL) {
        sgx_spin_unlock(&vfs_ops_lock);
        log_error("could not get metadata (%s)\n", filepath_IN);
        return -1;
    }

    // ACCESS CONTROL
    if (!bouncer_access_check(metadata, permission)) {
        log_error("ACCESS DENIED\n");
        goto out_err;
    }

    if (crypto_mode == NEXUS_ENCRYPT && filenode_set_filesize(metadata->filenode, filesize)) {
        log_error("filenode_set_filesize(%zu) FAILED\n", filesize);
        goto out_err;
    }


    // the file crypto takes control of the metadata object
    xfer_id = file_crypto_new(metadata, crypto_mode);

    if (xfer_id == -1) {
        log_error("file_crypto_new() FAILED\n");
        goto out_err;
    }


    if (filesize_out_opt) {
        *filesize_out_opt = metadata->filenode->filesize;
    }

    *xfer_id_out = xfer_id;

    nexus_uuid_copy(&metadata->uuid, uuid_out);

    sgx_spin_unlock(&vfs_ops_lock);

    return 0;

out_err:
    nexus_vfs_put(metadata);
    sgx_spin_unlock(&vfs_ops_lock);
    return -1;
}

int
ecall_fs_file_encrypt_start(char *              filepath_IN,
                            size_t              filesize,
                            int *               xfer_id_out,
                            struct nexus_uuid * uuid_out)
{
    return __nxs_file_crypto_start(filepath_IN, filesize, NEXUS_ENCRYPT, xfer_id_out, uuid_out, NULL);
}

int
ecall_fs_file_decrypt_start(char *              filepath_IN,
                            int *               xfer_id_out,
                            struct nexus_uuid * uuid_out,
                            size_t *            filesize_out)
{
    return __nxs_file_crypto_start(filepath_IN, 0, NEXUS_DECRYPT, xfer_id_out, uuid_out, filesize_out);
}


int
ecall_fs_file_crypto_seek(int xfer_id, int offset)
{
    return file_crypto_seek(xfer_id, offset);
}

int
ecall_fs_file_crypto_update(int       xfer_id,
                            uint8_t * input_buffer_in,
                            uint8_t * output_buffer_out,
                            size_t    size,
                            size_t *  processed_bytes)
{
    return file_crypto_update(xfer_id, input_buffer_in, output_buffer_out, size, processed_bytes);
}


int
ecall_fs_file_crypto_finish(int xfer_id)
{
    return file_crypto_finish(xfer_id);
}
