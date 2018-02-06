#include "internal.h"

int
sgx_backend_fs_create(struct nexus_volume * volume,
                      char                * path,
                      nexus_dirent_type_t   type,
                      struct nexus_stat   * stat,
                      void                * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    char * dirpath = NULL;
    char * filename = "foo.txt"; // TODO

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_create(sgx_backend->enclave_id, &ret, dirpath, filename, type, &uuid);

    if (err || ret) {
        log_error("ecall_fs_create() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}
