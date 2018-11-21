#include "internal.h"

int
sgx_backend_fs_create(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * name,
                      nexus_dirent_type_t    type,
                      nexus_file_mode_t      mode,
                      struct nexus_uuid    * uuid,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    BACKEND_SGX_ECALL_START(ECALL_CREATE);

    err = ecall_fs_create(sgx_backend->enclave_id, &ret, dirpath, name, type, mode, uuid);

    BACKEND_SGX_ECALL_FINISH(ECALL_CREATE);

    if (err || ret) {
        log_error("ecall_fs_create() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_remove(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      struct nexus_uuid    * uuid,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    BACKEND_SGX_ECALL_START(ECALL_REMOVE);

    err = ecall_fs_remove(sgx_backend->enclave_id, &ret, dirpath, plain_name, uuid);

    BACKEND_SGX_ECALL_FINISH(ECALL_REMOVE);

    if (err || ret) {
        log_error("ecall_fs_remove() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_lookup(struct nexus_volume    * volume,
                      char                   * dirpath,
                      char                   * plain_name,
                      struct nexus_fs_lookup * lookup_info,
                      void                   * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    BACKEND_SGX_ECALL_START(ECALL_LOOKUP);

    err = ecall_fs_lookup(sgx_backend->enclave_id, &ret, dirpath, plain_name, lookup_info);

    BACKEND_SGX_ECALL_FINISH(ECALL_LOOKUP);

    if (err) {
        log_error("ecall_fs_lookup() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return ret;
}

int
sgx_backend_fs_stat(struct nexus_volume * volume,
                    char                * path,
                    struct nexus_stat   * nexus_stat,
                    void                * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    BACKEND_SGX_ECALL_START(ECALL_STAT);

    err = ecall_fs_stat(sgx_backend->enclave_id, &ret, path, nexus_stat);

    BACKEND_SGX_ECALL_FINISH(ECALL_STAT);

    if (err) {
        log_error("ecall_fs_stat() FAILED. (err=0x%x)\n", err);
        return -1;
    }

    return ret;
}

int
sgx_backend_fs_filldir(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * nexus_name,
                       char                ** plain_name,
                       void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    char filename[NEXUS_NAME_MAX] = { 0 };

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    ret = nexus_uuid_from_alt64(&uuid, nexus_name);
    if (ret != 0) {
        log_error("could not derive uuid from '%s'\n", nexus_name);
        return -1;
    }

    BACKEND_SGX_ECALL_START(ECALL_FILLDIR);

    err = ecall_fs_filldir(sgx_backend->enclave_id, &ret, dirpath, &uuid, filename);

    BACKEND_SGX_ECALL_FINISH(ECALL_FILLDIR);

    if (err) {
        log_error("ecall_fs_filldir() FAILED. (err=0x%x)\n", err);
        return -1;
    }

    *plain_name = strndup(filename, NEXUS_NAME_MAX);

    return ret;
}

int
sgx_backend_fs_readdir(struct nexus_volume  * volume,
                       char                 * dirpath,
                       struct nexus_dirent  * dirent_buffer_array,
                       size_t                 dirent_buffer_count,
                       size_t                 offset,
                       size_t               * result_count,
                       size_t               * directory_size,
                       void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;


    // TODO add ECALL_READDIR
    err = ecall_fs_readdir(sgx_backend->enclave_id,
                           &ret,
                           dirpath,
                           dirent_buffer_array,
                           dirent_buffer_count,
                           offset,
                           result_count,
                           directory_size);

    if (err || ret) {
        log_error("ecall_fs_readdir() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_symlink(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * link_name,
                       char                 * target_path,
                       struct nexus_uuid    * uuid,
                       void                 * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int err = -1;
    int ret = -1;


    BACKEND_SGX_ECALL_START(ECALL_SYMLINK);

    err = ecall_fs_symlink(sgx_backend->enclave_id, &ret, dirpath, link_name, target_path, uuid);

    BACKEND_SGX_ECALL_FINISH(ECALL_SYMLINK);

    if (err || ret) {
        log_error("ecall_fs_symlink() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_readlink(struct nexus_volume  * volume,
                        char                 * dirpath,
                        char                 * linkname,
                        char                ** target,
                        void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    char result[NEXUS_PATH_MAX] = { 0 };

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    BACKEND_SGX_ECALL_START(ECALL_READLINK);

    err = ecall_fs_readlink(sgx_backend->enclave_id, &ret, dirpath, linkname, result);

    BACKEND_SGX_ECALL_FINISH(ECALL_READLINK);

    if (err || ret) {
        log_error("ecall_fs_readlink() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    *target = strndup(result, NEXUS_PATH_MAX);

    return 0;
}

int
sgx_backend_fs_hardlink(struct nexus_volume  * volume,
                        char                 * link_dirpath,
                        char                 * link_name,
                        char                 * target_dirpath,
                        char                 * target_name,
                        struct nexus_uuid    * uuid,
                        void                 * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int err = -1;
    int ret = -1;


    BACKEND_SGX_ECALL_START(ECALL_HARDLINK);

    err = ecall_fs_hardlink(sgx_backend->enclave_id,
                            &ret,
                            link_dirpath,
                            link_name,
                            target_dirpath,
                            target_name,
                            uuid);

    BACKEND_SGX_ECALL_FINISH(ECALL_HARDLINK);

    if (err || ret) {
        log_error("ecall_fs_hardlink() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}

int
sgx_backend_fs_rename(struct nexus_volume  * volume,
                      char                 * from_dirpath,
                      char                 * oldname,
                      char                 * to_dirpath,
                      char                 * newname,
                      struct nexus_uuid    * entry_uuid,
                      struct nexus_uuid    * overriden_uuid,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = (struct sgx_backend *)priv_data;

    int err = -1;
    int ret = -1;


    BACKEND_SGX_ECALL_START(ECALL_RENAME);

    err = ecall_fs_rename(sgx_backend->enclave_id,
                          &ret,
                          from_dirpath,
                          oldname,
                          to_dirpath,
                          newname,
                          entry_uuid,
                          overriden_uuid);

    BACKEND_SGX_ECALL_FINISH(ECALL_RENAME);

    if (err || ret) {
        log_error("ecall_fs_rename() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}
