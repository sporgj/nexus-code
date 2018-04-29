#include "internal.h"


int
sgx_backend_fs_encrypt(struct nexus_volume * volume,
                       char                * filepath,
                       uint8_t             * in_buf,
                       uint8_t             * out_buf,
                       size_t                offset,
                       size_t                size,
                       size_t                filesize,
                       void                * priv_data)

{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;


    if ((size < sgx_backend->volume_chunk_size) && (size + offset != filesize)) {
        log_error("invalid encryption arguments (offset=%zu, size=%zu < filesize=%zu)\n",
                  offset,
                  size,
                  filesize);

        return -1;
    }

    err = ecall_fs_encrypt(sgx_backend->enclave_id,
                           &ret,
                           filepath,
                           in_buf,
                           out_buf,
                           offset,
                           size,
                           filesize);

    if (err || ret) {
        log_error("ecall_fs_encrypt (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_decrypt(struct nexus_volume * volume,
                       char                * filepath,
                       uint8_t             * in_buf,
                       uint8_t             * out_buf,
                       size_t                offset,
                       size_t                size,
                       size_t                filesize,
                       void                * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;


    if ((size < sgx_backend->volume_chunk_size) && (size + offset != filesize)) {
        log_error("invalid decryption arguments (offset=%zu, size=%zu < filesize=%zu)\n",
                  offset,
                  size,
                  filesize);

        return -1;
    }

    err = ecall_fs_decrypt(sgx_backend->enclave_id,
                           &ret,
                           filepath,
                           in_buf,
                           out_buf,
                           offset,
                           size,
                           filesize);

    if (err || ret) {
        log_error("ecall_fs_decrypt (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}