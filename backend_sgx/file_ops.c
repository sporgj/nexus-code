#include "internal.h"


struct nexus_file_crypto *
sgx_backend_fs_file_encrypt_start(struct nexus_volume * volume,
                                  char                * filepath,
                                  size_t                filesize,
                                  void                * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int trusted_xfer_id = -1;

    int err = -1;
    int ret = -1;

    err = ecall_fs_file_encrypt_start(sgx_backend->enclave_id,
                                      &ret,
                                      filepath,
                                      filesize,
                                      &trusted_xfer_id);

    if (err || ret) {
        log_error("ecall_fs_file_encrypt_start (err=%d, ret=%d)\n", err, ret);
        return NULL;
    }

    return io_file_crypto_start(trusted_xfer_id, FILE_ENCRYPT, filepath, sgx_backend);
}

struct nexus_file_crypto *
sgx_backend_fs_file_decrypt_start(struct nexus_volume * volume, char * filepath, void * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int trusted_xfer_id = -1;

    int err = -1;
    int ret = -1;

    err = ecall_fs_file_decrypt_start(sgx_backend->enclave_id,
                                      &ret,
                                      filepath,
                                      &trusted_xfer_id);

    if (err || ret) {
        log_error("ecall_fs_file_encrypt_start (err=%d, ret=%d)\n", err, ret);
        return NULL;
    }

    return io_file_crypto_start(trusted_xfer_id, FILE_DECRYPT, filepath, sgx_backend);
}

int
sgx_backend_fs_file_crypto_seek(struct nexus_file_crypto * file_crypto, size_t offset)
{
    int err = -1;
    int ret = -1;

    err = ecall_fs_file_crypto_seek(file_crypto->sgx_backend->enclave_id,
                                    &ret,
                                    file_crypto->trusted_xfer_id,
                                    offset);

    if (err || ret) {
        log_error("ecall_fs_file_crypto_seek (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return io_file_crypto_seek(file_crypto, offset);
}

int
sgx_backend_fs_file_crypto_update(struct nexus_file_crypto * file_crypto,
                                  const uint8_t            * input,
                                  uint8_t                  * output,
                                  size_t                     size,
                                  size_t                   * processed_bytes)
{
    int err = -1;
    int ret = -1;

    err = ecall_fs_file_crypto_update(file_crypto->sgx_backend->enclave_id,
                                      &ret,
                                      file_crypto->trusted_xfer_id,
                                      (uint8_t *)input,
                                      output,
                                      size,
                                      processed_bytes);

    if (err || ret) {
        log_error("ecall_fs_file_crypto_seek (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return io_file_crypto_update(file_crypto, input, output, *processed_bytes);
}

int sgx_backend_fs_file_crypto_finish(struct nexus_file_crypto * file_crypto)
{
    int err = -1;
    int ret = -1;

    err = ecall_fs_file_crypto_finish(file_crypto->sgx_backend->enclave_id, &ret, file_crypto->trusted_xfer_id);

    if (err || ret) {
        log_error("ecall_fs_file_crypto_finish (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return io_file_crypto_finish(file_crypto);
}
