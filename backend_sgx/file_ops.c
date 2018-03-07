#include "internal.h"


int
sgx_backend_encrypt(struct nexus_volume * volume,
                    char                * filepath,
                    uint8_t             * in_buf,
                    uint8_t             * out_buf,
                    off_t                 offset,
                    size_t                size,
                    size_t                filesize,
                    size_t              * left_over,
                    void                * priv_data)

{
    struct sgx_backend * sgx_backend = NULL;

    bool has_completed_chunk = false;

    size_t curr_offset = 0;
    int    nbytes      = 0;
    int    bytes_left  = 0;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;


    curr_offset = offset;
    bytes_left  = size;

next_chunk:
    if (bytes_left < (int) sgx_backend->volume_chunk_size) {
        if (bytes_left + curr_offset != filesize) {
            log_error("invalid encryption arguments (offset=%zu, "
                      "bytes_left=%d < filesize=%zu)\n",
                      curr_offset,
                      bytes_left,
                      filesize);

            *left_over = bytes_left;

            return has_completed_chunk ? 0 : -1;
        }
    }

    nbytes = min(size, sgx_backend->volume_chunk_size);

    err = ecall_fs_encrypt(sgx_backend->enclave_id, &ret, filepath, in_buf, out_buf, nbytes, offset, filesize);

    if (err || ret == -1) {
        log_error("ecall_fs_encrypt (err=%d, ret=%d)\n", err, ret);
        return -1;
    }

    has_completed_chunk = true;

    bytes_left -= nbytes;

    if (bytes_left > 0) {
        goto next_chunk;
    }

    return 0;
}
