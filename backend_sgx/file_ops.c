#include "internal.h"


struct nexus_file_crypto *
sgx_backend_fs_file_encrypt_start(struct nexus_volume * volume,
                                  char                * filepath,
                                  size_t                filesize,
                                  void                * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    struct nexus_uuid uuid;

    int trusted_xfer_id = -1;

    int err = -1;
    int ret = -1;

    err = ecall_fs_file_encrypt_start(sgx_backend->enclave_id,
                                      &ret,
                                      filepath,
                                      filesize,
                                      &trusted_xfer_id,
                                      &uuid);

    if (err || ret) {
        log_error("ecall_fs_file_encrypt_start (err=%d, ret=%d)\n", err, ret);
        return NULL;
    }

    return io_file_crypto_start(trusted_xfer_id, &uuid, FILE_ENCRYPT, filesize, filepath, sgx_backend);
}

struct nexus_file_crypto *
sgx_backend_fs_file_decrypt_start(struct nexus_volume * volume, char * filepath, void * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    struct nexus_uuid uuid;

    size_t filesize = 0;

    int trusted_xfer_id = -1;

    int err = -1;
    int ret = -1;


    err = ecall_fs_file_decrypt_start(sgx_backend->enclave_id,
                                      &ret,
                                      filepath,
                                      &trusted_xfer_id,
                                      &uuid,
                                      &filesize);

    if (err || ret) {
        log_error("ecall_fs_file_encrypt_start (err=%d, ret=%d)\n", err, ret);
        return NULL;
    }

    return io_file_crypto_start(trusted_xfer_id, &uuid, FILE_DECRYPT, filesize, filepath, sgx_backend);
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
sgx_backend_fs_file_crypto_encrypt(struct nexus_file_crypto * file_crypto,
                                   const uint8_t            * plaintext_input,
                                   uint8_t                  * encrypted_output,
                                   size_t                     size,
                                   size_t                   * processed_bytes)
{
    int err = -1;
    int ret = -1;

    err = ecall_fs_file_crypto_update(file_crypto->sgx_backend->enclave_id,
                                      &ret,
                                      file_crypto->trusted_xfer_id,
                                      (uint8_t *)plaintext_input,
                                      encrypted_output,
                                      size,
                                      processed_bytes);

    if (err || ret) {
        log_error("ecall_fs_file_crypto_update (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return io_file_crypto_write(file_crypto, encrypted_output, *processed_bytes);
}

int
sgx_backend_fs_file_crypto_decrypt(struct nexus_file_crypto * file_crypto,
                                   uint8_t                  * decrypted_output,
                                   size_t                     size,
                                   size_t                   * processed_bytes)
{
    int err = -1;
    int ret = -1;


    if (io_file_crypto_read(file_crypto, decrypted_output, size)) {
        log_error("io_file_crypto_read() FAILED\n");
        return -1;
    }


    err = ecall_fs_file_crypto_update(file_crypto->sgx_backend->enclave_id,
                                      &ret,
                                      file_crypto->trusted_xfer_id,
                                      decrypted_output,
                                      decrypted_output,
                                      size,
                                      processed_bytes);

    if (err || ret) {
        log_error("ecall_fs_file_crypto_update (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_file_crypto_finish(struct nexus_file_crypto * file_crypto)
{
    int err = -1;
    int ret = -1;

    err = ecall_fs_file_crypto_finish(file_crypto->sgx_backend->enclave_id, &ret, file_crypto->trusted_xfer_id);

    if (err || ret) {
        log_error("ecall_fs_file_crypto_finish (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    // FIXME: VERY BAD design, this should be from an OCALL
    return io_file_crypto_finish(file_crypto);
}

int
sgx_backend_fs_truncate(struct nexus_volume * volume,
                        char                * filepath,
                        size_t                filesize,
                        struct nexus_stat   * stat,
                        void                * priv_data)
{
    struct sgx_backend * sgx_backend = priv_data;

    int err = -1;
    int ret = -1;


    err = ecall_fs_truncate(sgx_backend->enclave_id, &ret, filepath, filesize, stat);

    if (err || ret) {
        log_error("ecall_fs_truncate() FAILED\n");
        return -1;
    }

    // FIXME: this is VERY VERY BAD, this must come in as an OCALL.
    if (io_buffer_truncate(&stat->uuid, filesize, sgx_backend)) {
        log_error("io_buffer_truncate() FAILED\n");
        return -1;
    }

    return 0;
}
